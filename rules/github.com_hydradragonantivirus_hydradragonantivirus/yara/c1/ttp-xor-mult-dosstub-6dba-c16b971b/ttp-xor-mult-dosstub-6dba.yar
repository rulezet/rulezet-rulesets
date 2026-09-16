rule TTP_XOR_MULT_DOSStub_6dba {
  strings:
    $key_6dba = { 39 d2 [2] 4d ca [2] 0a c8 [2] 4d d9 [2] 03 d5 [2] 0f df [2] 18 d4 [2] 03 9a [2] 3e }

  condition:
    any of them
}