rule TTP_XOR_MULT_DOSStub_7230 {
  strings:
    $key_7230 = { 26 58 [2] 52 40 [2] 15 42 [2] 52 53 [2] 1c 5f [2] 10 55 [2] 07 5e [2] 1c 10 [2] 21 }

  condition:
    any of them
}