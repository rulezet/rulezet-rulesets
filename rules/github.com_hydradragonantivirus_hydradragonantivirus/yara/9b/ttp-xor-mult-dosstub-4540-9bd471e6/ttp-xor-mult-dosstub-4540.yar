rule TTP_XOR_MULT_DOSStub_4540 {
  strings:
    $key_4540 = { 11 28 [2] 65 30 [2] 22 32 [2] 65 23 [2] 2b 2f [2] 27 25 [2] 30 2e [2] 2b 60 [2] 16 }

  condition:
    any of them
}