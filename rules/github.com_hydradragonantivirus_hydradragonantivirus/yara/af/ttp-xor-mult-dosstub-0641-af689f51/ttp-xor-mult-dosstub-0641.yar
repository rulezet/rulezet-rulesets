rule TTP_XOR_MULT_DOSStub_0641 {
  strings:
    $key_0641 = { 52 29 [2] 26 31 [2] 61 33 [2] 26 22 [2] 68 2e [2] 64 24 [2] 73 2f [2] 68 61 [2] 55 }

  condition:
    any of them
}