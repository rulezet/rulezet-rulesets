rule TTP_XOR_MULT_DOSStub_4440 {
  strings:
    $key_4440 = { 10 28 [2] 64 30 [2] 23 32 [2] 64 23 [2] 2a 2f [2] 26 25 [2] 31 2e [2] 2a 60 [2] 17 }

  condition:
    any of them
}