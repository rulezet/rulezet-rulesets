rule TTP_XOR_MULT_DOSStub_f966 {
  strings:
    $key_f966 = { ad 0e [2] d9 16 [2] 9e 14 [2] d9 05 [2] 97 09 [2] 9b 03 [2] 8c 08 [2] 97 46 [2] aa }

  condition:
    any of them
}