rule TTP_XOR_MULT_DOSStub_7036 {
  strings:
    $key_7036 = { 24 5e [2] 50 46 [2] 17 44 [2] 50 55 [2] 1e 59 [2] 12 53 [2] 05 58 [2] 1e 16 [2] 23 }

  condition:
    any of them
}