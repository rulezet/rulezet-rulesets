rule TTP_XOR_MULT_DOSStub_0047 {
  strings:
    $key_0047 = { 54 2f [2] 20 37 [2] 67 35 [2] 20 24 [2] 6e 28 [2] 62 22 [2] 75 29 [2] 6e 67 [2] 53 }

  condition:
    any of them
}