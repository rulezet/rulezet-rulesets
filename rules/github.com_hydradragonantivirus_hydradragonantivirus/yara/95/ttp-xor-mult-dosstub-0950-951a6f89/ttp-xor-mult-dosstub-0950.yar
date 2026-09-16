rule TTP_XOR_MULT_DOSStub_0950 {
  strings:
    $key_0950 = { 5d 38 [2] 29 20 [2] 6e 22 [2] 29 33 [2] 67 3f [2] 6b 35 [2] 7c 3e [2] 67 70 [2] 5a }

  condition:
    any of them
}