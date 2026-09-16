rule TTP_XOR_MULT_DOSStub_f990 {
  strings:
    $key_f990 = { ad f8 [2] d9 e0 [2] 9e e2 [2] d9 f3 [2] 97 ff [2] 9b f5 [2] 8c fe [2] 97 b0 [2] aa }

  condition:
    any of them
}