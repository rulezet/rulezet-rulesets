rule TTP_XOR_MULT_DOSStub_3c30 {
  strings:
    $key_3c30 = { 68 58 [2] 1c 40 [2] 5b 42 [2] 1c 53 [2] 52 5f [2] 5e 55 [2] 49 5e [2] 52 10 [2] 6f }

  condition:
    any of them
}