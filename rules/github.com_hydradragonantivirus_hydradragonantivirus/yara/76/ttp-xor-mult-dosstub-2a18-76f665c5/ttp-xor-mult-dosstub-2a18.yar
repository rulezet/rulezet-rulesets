rule TTP_XOR_MULT_DOSStub_2a18 {
  strings:
    $key_2a18 = { 7e 70 [2] 0a 68 [2] 4d 6a [2] 0a 7b [2] 44 77 [2] 48 7d [2] 5f 76 [2] 44 38 [2] 79 }

  condition:
    any of them
}