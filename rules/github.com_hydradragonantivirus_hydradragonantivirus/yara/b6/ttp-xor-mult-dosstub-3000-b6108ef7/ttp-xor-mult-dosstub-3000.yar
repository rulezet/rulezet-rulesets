rule TTP_XOR_MULT_DOSStub_3000 {
  strings:
    $key_3000 = { 64 68 [2] 10 70 [2] 57 72 [2] 10 63 [2] 5e 6f [2] 52 65 [2] 45 6e [2] 5e 20 [2] 63 }

  condition:
    any of them
}