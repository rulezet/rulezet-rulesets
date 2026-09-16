rule TTP_XOR_MULT_DOSStub_0951 {
  strings:
    $key_0951 = { 5d 39 [2] 29 21 [2] 6e 23 [2] 29 32 [2] 67 3e [2] 6b 34 [2] 7c 3f [2] 67 71 [2] 5a }

  condition:
    any of them
}