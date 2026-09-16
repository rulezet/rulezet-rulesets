rule TTP_XOR_MULT_DOSStub_08f0 {
  strings:
    $key_08f0 = { 5c 98 [2] 28 80 [2] 6f 82 [2] 28 93 [2] 66 9f [2] 6a 95 [2] 7d 9e [2] 66 d0 [2] 5b }

  condition:
    any of them
}