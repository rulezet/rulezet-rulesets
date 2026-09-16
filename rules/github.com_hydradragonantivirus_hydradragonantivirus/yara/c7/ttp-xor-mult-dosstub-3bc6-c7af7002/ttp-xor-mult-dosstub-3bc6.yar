rule TTP_XOR_MULT_DOSStub_3bc6 {
  strings:
    $key_3bc6 = { 6f ae [2] 1b b6 [2] 5c b4 [2] 1b a5 [2] 55 a9 [2] 59 a3 [2] 4e a8 [2] 55 e6 [2] 68 }

  condition:
    any of them
}