rule TTP_XOR_MULT_DOSStub_e991 {
  strings:
    $key_e991 = { bd f9 [2] c9 e1 [2] 8e e3 [2] c9 f2 [2] 87 fe [2] 8b f4 [2] 9c ff [2] 87 b1 [2] ba }

  condition:
    any of them
}