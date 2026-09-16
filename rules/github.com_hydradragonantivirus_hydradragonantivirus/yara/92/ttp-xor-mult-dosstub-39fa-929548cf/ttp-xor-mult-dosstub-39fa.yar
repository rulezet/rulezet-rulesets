rule TTP_XOR_MULT_DOSStub_39fa {
  strings:
    $key_39fa = { 6d 92 [2] 19 8a [2] 5e 88 [2] 19 99 [2] 57 95 [2] 5b 9f [2] 4c 94 [2] 57 da [2] 6a }

  condition:
    any of them
}