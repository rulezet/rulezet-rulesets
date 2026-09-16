rule TTP_XOR_MULT_DOSStub_44f8 {
  strings:
    $key_44f8 = { 10 90 [2] 64 88 [2] 23 8a [2] 64 9b [2] 2a 97 [2] 26 9d [2] 31 96 [2] 2a d8 [2] 17 }

  condition:
    any of them
}