rule TTP_XOR_MULT_DOSStub_38f0 {
  strings:
    $key_38f0 = { 6c 98 [2] 18 80 [2] 5f 82 [2] 18 93 [2] 56 9f [2] 5a 95 [2] 4d 9e [2] 56 d0 [2] 6b }

  condition:
    any of them
}