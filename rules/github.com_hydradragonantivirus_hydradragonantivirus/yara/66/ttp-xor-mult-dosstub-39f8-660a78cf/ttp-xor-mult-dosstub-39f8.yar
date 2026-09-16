rule TTP_XOR_MULT_DOSStub_39f8 {
  strings:
    $key_39f8 = { 6d 90 [2] 19 88 [2] 5e 8a [2] 19 9b [2] 57 97 [2] 5b 9d [2] 4c 96 [2] 57 d8 [2] 6a }

  condition:
    any of them
}