rule TTP_XOR_MULT_DOSStub_2dba {
  strings:
    $key_2dba = { 79 d2 [2] 0d ca [2] 4a c8 [2] 0d d9 [2] 43 d5 [2] 4f df [2] 58 d4 [2] 43 9a [2] 7e }

  condition:
    any of them
}