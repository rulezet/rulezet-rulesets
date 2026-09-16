rule TTP_XOR_MULT_DOSStub_7430 {
  strings:
    $key_7430 = { 20 58 [2] 54 40 [2] 13 42 [2] 54 53 [2] 1a 5f [2] 16 55 [2] 01 5e [2] 1a 10 [2] 27 }

  condition:
    any of them
}