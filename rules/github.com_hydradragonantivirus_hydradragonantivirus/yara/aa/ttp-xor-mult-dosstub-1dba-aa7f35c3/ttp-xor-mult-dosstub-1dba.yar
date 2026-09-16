rule TTP_XOR_MULT_DOSStub_1dba {
  strings:
    $key_1dba = { 49 d2 [2] 3d ca [2] 7a c8 [2] 3d d9 [2] 73 d5 [2] 7f df [2] 68 d4 [2] 73 9a [2] 4e }

  condition:
    any of them
}