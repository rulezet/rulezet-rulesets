rule TTP_XOR_MULT_DOSStub_0b51 {
  strings:
    $key_0b51 = { 5f 39 [2] 2b 21 [2] 6c 23 [2] 2b 32 [2] 65 3e [2] 69 34 [2] 7e 3f [2] 65 71 [2] 58 }

  condition:
    any of them
}