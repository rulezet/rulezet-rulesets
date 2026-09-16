rule TTP_XOR_MULT_DOSStub_1959 {
  strings:
    $key_1959 = { 4d 31 [2] 39 29 [2] 7e 2b [2] 39 3a [2] 77 36 [2] 7b 3c [2] 6c 37 [2] 77 79 [2] 4a }

  condition:
    any of them
}