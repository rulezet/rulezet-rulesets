rule TTP_XOR_MULT_DOSStub_38f6 {
  strings:
    $key_38f6 = { 6c 9e [2] 18 86 [2] 5f 84 [2] 18 95 [2] 56 99 [2] 5a 93 [2] 4d 98 [2] 56 d6 [2] 6b }

  condition:
    any of them
}