rule TTP_XOR_MULT_DOSStub_0031 {
  strings:
    $key_0031 = { 54 59 [2] 20 41 [2] 67 43 [2] 20 52 [2] 6e 5e [2] 62 54 [2] 75 5f [2] 6e 11 [2] 53 }

  condition:
    any of them
}