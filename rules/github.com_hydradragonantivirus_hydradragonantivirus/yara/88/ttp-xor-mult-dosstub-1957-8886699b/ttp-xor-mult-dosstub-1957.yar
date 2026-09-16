rule TTP_XOR_MULT_DOSStub_1957 {
  strings:
    $key_1957 = { 4d 3f [2] 39 27 [2] 7e 25 [2] 39 34 [2] 77 38 [2] 7b 32 [2] 6c 39 [2] 77 77 [2] 4a }

  condition:
    any of them
}