rule TTP_XOR_MULT_DOSStub_1a51 {
  strings:
    $key_1a51 = { 4e 39 [2] 3a 21 [2] 7d 23 [2] 3a 32 [2] 74 3e [2] 78 34 [2] 6f 3f [2] 74 71 [2] 49 }

  condition:
    any of them
}