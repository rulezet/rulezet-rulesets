rule TTP_XOR_MULT_DOSStub_4430 {
  strings:
    $key_4430 = { 10 58 [2] 64 40 [2] 23 42 [2] 64 53 [2] 2a 5f [2] 26 55 [2] 31 5e [2] 2a 10 [2] 17 }

  condition:
    any of them
}