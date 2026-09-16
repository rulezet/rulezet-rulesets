rule TTP_XOR_MULT_DOSStub_3060 {
  strings:
    $key_3060 = { 64 08 [2] 10 10 [2] 57 12 [2] 10 03 [2] 5e 0f [2] 52 05 [2] 45 0e [2] 5e 40 [2] 63 }

  condition:
    any of them
}