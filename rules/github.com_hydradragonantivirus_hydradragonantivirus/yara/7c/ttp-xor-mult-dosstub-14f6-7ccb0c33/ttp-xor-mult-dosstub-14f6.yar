rule TTP_XOR_MULT_DOSStub_14f6 {
  strings:
    $key_14f6 = { 40 9e [2] 34 86 [2] 73 84 [2] 34 95 [2] 7a 99 [2] 76 93 [2] 61 98 [2] 7a d6 [2] 47 }

  condition:
    any of them
}