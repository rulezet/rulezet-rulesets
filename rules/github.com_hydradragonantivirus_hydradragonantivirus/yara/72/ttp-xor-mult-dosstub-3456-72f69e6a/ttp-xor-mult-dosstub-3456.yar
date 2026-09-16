rule TTP_XOR_MULT_DOSStub_3456 {
  strings:
    $key_3456 = { 60 3e [2] 14 26 [2] 53 24 [2] 14 35 [2] 5a 39 [2] 56 33 [2] 41 38 [2] 5a 76 [2] 67 }

  condition:
    any of them
}