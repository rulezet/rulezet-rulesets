rule TTP_XOR_MULT_DOSStub_7b30 {
  strings:
    $key_7b30 = { 2f 58 [2] 5b 40 [2] 1c 42 [2] 5b 53 [2] 15 5f [2] 19 55 [2] 0e 5e [2] 15 10 [2] 28 }

  condition:
    any of them
}