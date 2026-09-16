rule TTP_XOR_MULT_DOSStub_0a06 {
  strings:
    $key_0a06 = { 5e 6e [2] 2a 76 [2] 6d 74 [2] 2a 65 [2] 64 69 [2] 68 63 [2] 7f 68 [2] 64 26 [2] 59 }

  condition:
    any of them
}