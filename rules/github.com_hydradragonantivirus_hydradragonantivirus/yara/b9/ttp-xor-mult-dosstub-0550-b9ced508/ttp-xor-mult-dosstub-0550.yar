rule TTP_XOR_MULT_DOSStub_0550 {
  strings:
    $key_0550 = { 51 38 [2] 25 20 [2] 62 22 [2] 25 33 [2] 6b 3f [2] 67 35 [2] 70 3e [2] 6b 70 [2] 56 }

  condition:
    any of them
}