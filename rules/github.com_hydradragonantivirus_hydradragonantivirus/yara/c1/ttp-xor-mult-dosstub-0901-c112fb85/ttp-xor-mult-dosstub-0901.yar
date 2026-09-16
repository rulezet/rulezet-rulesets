rule TTP_XOR_MULT_DOSStub_0901 {
  strings:
    $key_0901 = { 5d 69 [2] 29 71 [2] 6e 73 [2] 29 62 [2] 67 6e [2] 6b 64 [2] 7c 6f [2] 67 21 [2] 5a }

  condition:
    any of them
}