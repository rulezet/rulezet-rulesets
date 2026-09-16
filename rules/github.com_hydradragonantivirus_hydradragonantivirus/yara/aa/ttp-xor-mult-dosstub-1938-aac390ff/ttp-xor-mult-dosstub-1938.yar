rule TTP_XOR_MULT_DOSStub_1938 {
  strings:
    $key_1938 = { 4d 50 [2] 39 48 [2] 7e 4a [2] 39 5b [2] 77 57 [2] 7b 5d [2] 6c 56 [2] 77 18 [2] 4a }

  condition:
    any of them
}