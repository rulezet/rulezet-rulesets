rule TTP_XOR_MULT_DOSStub_0001 {
  strings:
    $key_0001 = { 54 69 [2] 20 71 [2] 67 73 [2] 20 62 [2] 6e 6e [2] 62 64 [2] 75 6f [2] 6e 21 [2] 53 }

  condition:
    any of them
}