rule TTP_XOR_MULT_DOSStub_0906 {
  strings:
    $key_0906 = { 5d 6e [2] 29 76 [2] 6e 74 [2] 29 65 [2] 67 69 [2] 6b 63 [2] 7c 68 [2] 67 26 [2] 5a }

  condition:
    any of them
}