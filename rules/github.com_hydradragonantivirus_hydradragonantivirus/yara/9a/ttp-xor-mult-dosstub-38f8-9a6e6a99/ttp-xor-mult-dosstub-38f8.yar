rule TTP_XOR_MULT_DOSStub_38f8 {
  strings:
    $key_38f8 = { 6c 90 [2] 18 88 [2] 5f 8a [2] 18 9b [2] 56 97 [2] 5a 9d [2] 4d 96 [2] 56 d8 [2] 6b }

  condition:
    any of them
}