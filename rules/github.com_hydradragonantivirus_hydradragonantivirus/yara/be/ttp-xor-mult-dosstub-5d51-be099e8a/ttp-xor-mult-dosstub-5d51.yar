rule TTP_XOR_MULT_DOSStub_5d51 {
  strings:
    $key_5d51 = { 09 39 [2] 7d 21 [2] 3a 23 [2] 7d 32 [2] 33 3e [2] 3f 34 [2] 28 3f [2] 33 71 [2] 0e }

  condition:
    any of them
}