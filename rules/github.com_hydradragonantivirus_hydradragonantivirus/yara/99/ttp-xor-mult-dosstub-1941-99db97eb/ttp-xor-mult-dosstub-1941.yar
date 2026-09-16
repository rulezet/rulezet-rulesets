rule TTP_XOR_MULT_DOSStub_1941 {
  strings:
    $key_1941 = { 4d 29 [2] 39 31 [2] 7e 33 [2] 39 22 [2] 77 2e [2] 7b 24 [2] 6c 2f [2] 77 61 [2] 4a }

  condition:
    any of them
}