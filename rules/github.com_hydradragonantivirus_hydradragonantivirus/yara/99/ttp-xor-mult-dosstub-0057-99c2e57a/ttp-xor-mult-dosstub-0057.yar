rule TTP_XOR_MULT_DOSStub_0057 {
  strings:
    $key_0057 = { 54 3f [2] 20 27 [2] 67 25 [2] 20 34 [2] 6e 38 [2] 62 32 [2] 75 39 [2] 6e 77 [2] 53 }

  condition:
    any of them
}