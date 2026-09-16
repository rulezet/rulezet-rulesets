rule TTP_XOR_MULT_DOSStub_f991 {
  strings:
    $key_f991 = { ad f9 [2] d9 e1 [2] 9e e3 [2] d9 f2 [2] 97 fe [2] 9b f4 [2] 8c ff [2] 97 b1 [2] aa }

  condition:
    any of them
}