rule TTP_XOR_MULT_DOSStub_7930 {
  strings:
    $key_7930 = { 2d 58 [2] 59 40 [2] 1e 42 [2] 59 53 [2] 17 5f [2] 1b 55 [2] 0c 5e [2] 17 10 [2] 2a }

  condition:
    any of them
}