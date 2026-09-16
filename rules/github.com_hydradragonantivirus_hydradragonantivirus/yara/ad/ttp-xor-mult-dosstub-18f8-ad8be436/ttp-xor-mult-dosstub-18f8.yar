rule TTP_XOR_MULT_DOSStub_18f8 {
  strings:
    $key_18f8 = { 4c 90 [2] 38 88 [2] 7f 8a [2] 38 9b [2] 76 97 [2] 7a 9d [2] 6d 96 [2] 76 d8 [2] 4b }

  condition:
    any of them
}