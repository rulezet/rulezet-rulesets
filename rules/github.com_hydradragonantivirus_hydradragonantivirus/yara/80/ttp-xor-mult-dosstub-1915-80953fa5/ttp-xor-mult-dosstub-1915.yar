rule TTP_XOR_MULT_DOSStub_1915 {
  strings:
    $key_1915 = { 4d 7d [2] 39 65 [2] 7e 67 [2] 39 76 [2] 77 7a [2] 7b 70 [2] 6c 7b [2] 77 35 [2] 4a }

  condition:
    any of them
}