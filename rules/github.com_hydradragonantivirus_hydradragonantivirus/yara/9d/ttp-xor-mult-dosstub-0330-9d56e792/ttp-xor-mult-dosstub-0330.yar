rule TTP_XOR_MULT_DOSStub_0330 {
  strings:
    $key_0330 = { 57 58 [2] 23 40 [2] 64 42 [2] 23 53 [2] 6d 5f [2] 61 55 [2] 76 5e [2] 6d 10 [2] 50 }

  condition:
    any of them
}