rule TTP_XOR_MULT_DOSStub_2d30 {
  strings:
    $key_2d30 = { 79 58 [2] 0d 40 [2] 4a 42 [2] 0d 53 [2] 43 5f [2] 4f 55 [2] 58 5e [2] 43 10 [2] 7e }

  condition:
    any of them
}