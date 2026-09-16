rule TTP_XOR_MULT_DOSStub_48bc {
  strings:
    $key_48bc = { 1c d4 [2] 68 cc [2] 2f ce [2] 68 df [2] 26 d3 [2] 2a d9 [2] 3d d2 [2] 26 9c [2] 1b }

  condition:
    any of them
}