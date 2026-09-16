rule TTP_XOR_MULT_DOSStub_0240 {
  strings:
    $key_0240 = { 56 28 [2] 22 30 [2] 65 32 [2] 22 23 [2] 6c 2f [2] 60 25 [2] 77 2e [2] 6c 60 [2] 51 }

  condition:
    any of them
}