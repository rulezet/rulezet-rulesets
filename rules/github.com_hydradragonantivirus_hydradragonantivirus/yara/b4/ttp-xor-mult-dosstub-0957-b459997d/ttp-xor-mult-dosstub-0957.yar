rule TTP_XOR_MULT_DOSStub_0957 {
  strings:
    $key_0957 = { 5d 3f [2] 29 27 [2] 6e 25 [2] 29 34 [2] 67 38 [2] 6b 32 [2] 7c 39 [2] 67 77 [2] 5a }

  condition:
    any of them
}