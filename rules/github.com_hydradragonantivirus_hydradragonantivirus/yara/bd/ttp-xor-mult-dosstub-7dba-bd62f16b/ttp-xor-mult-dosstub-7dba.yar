rule TTP_XOR_MULT_DOSStub_7dba {
  strings:
    $key_7dba = { 29 d2 [2] 5d ca [2] 1a c8 [2] 5d d9 [2] 13 d5 [2] 1f df [2] 08 d4 [2] 13 9a [2] 2e }

  condition:
    any of them
}