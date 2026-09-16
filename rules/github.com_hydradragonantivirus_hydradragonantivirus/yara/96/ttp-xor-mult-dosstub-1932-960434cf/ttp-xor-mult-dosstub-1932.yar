rule TTP_XOR_MULT_DOSStub_1932 {
  strings:
    $key_1932 = { 4d 5a [2] 39 42 [2] 7e 40 [2] 39 51 [2] 77 5d [2] 7b 57 [2] 6c 5c [2] 77 12 [2] 4a }

  condition:
    any of them
}