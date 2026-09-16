rule TTP_XOR_MULT_DOSStub_0020 {
  strings:
    $key_0020 = { 54 48 [2] 20 50 [2] 67 52 [2] 20 43 [2] 6e 4f [2] 62 45 [2] 75 4e [2] 6e 00 [2] 53 }

  condition:
    any of them
}