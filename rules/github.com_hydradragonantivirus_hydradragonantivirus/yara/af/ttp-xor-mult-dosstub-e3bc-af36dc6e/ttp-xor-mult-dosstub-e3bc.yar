rule TTP_XOR_MULT_DOSStub_e3bc {
  strings:
    $key_e3bc = { b7 d4 [2] c3 cc [2] 84 ce [2] c3 df [2] 8d d3 [2] 81 d9 [2] 96 d2 [2] 8d 9c [2] b0 }

  condition:
    any of them
}