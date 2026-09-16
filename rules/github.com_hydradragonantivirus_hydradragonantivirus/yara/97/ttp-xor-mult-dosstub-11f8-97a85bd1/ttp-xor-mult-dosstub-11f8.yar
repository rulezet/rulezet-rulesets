rule TTP_XOR_MULT_DOSStub_11f8 {
  strings:
    $key_11f8 = { 45 90 [2] 31 88 [2] 76 8a [2] 31 9b [2] 7f 97 [2] 73 9d [2] 64 96 [2] 7f d8 [2] 42 }

  condition:
    any of them
}