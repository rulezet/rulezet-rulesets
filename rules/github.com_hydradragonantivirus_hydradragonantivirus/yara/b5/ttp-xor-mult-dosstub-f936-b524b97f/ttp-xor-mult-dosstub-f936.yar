rule TTP_XOR_MULT_DOSStub_f936 {
  strings:
    $key_f936 = { ad 5e [2] d9 46 [2] 9e 44 [2] d9 55 [2] 97 59 [2] 9b 53 [2] 8c 58 [2] 97 16 [2] aa }

  condition:
    any of them
}