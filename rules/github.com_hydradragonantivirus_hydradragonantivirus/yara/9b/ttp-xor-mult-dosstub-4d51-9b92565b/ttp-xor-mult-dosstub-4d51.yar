rule TTP_XOR_MULT_DOSStub_4d51 {
  strings:
    $key_4d51 = { 19 39 [2] 6d 21 [2] 2a 23 [2] 6d 32 [2] 23 3e [2] 2f 34 [2] 38 3f [2] 23 71 [2] 1e }

  condition:
    any of them
}