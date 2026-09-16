rule TTP_XOR_MULT_DOSStub_7d16 {
  strings:
    $key_7d16 = { 29 7e [2] 5d 66 [2] 1a 64 [2] 5d 75 [2] 13 79 [2] 1f 73 [2] 08 78 [2] 13 36 [2] 2e }

  condition:
    any of them
}