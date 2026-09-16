rule TTP_XOR_MULT_DOSStub_7d51 {
  strings:
    $key_7d51 = { 29 39 [2] 5d 21 [2] 1a 23 [2] 5d 32 [2] 13 3e [2] 1f 34 [2] 08 3f [2] 13 71 [2] 2e }

  condition:
    any of them
}