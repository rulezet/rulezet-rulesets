rule TTP_XOR_MULT_DOSStub_7b51 {
  strings:
    $key_7b51 = { 2f 39 [2] 5b 21 [2] 1c 23 [2] 5b 32 [2] 15 3e [2] 19 34 [2] 0e 3f [2] 15 71 [2] 28 }

  condition:
    any of them
}