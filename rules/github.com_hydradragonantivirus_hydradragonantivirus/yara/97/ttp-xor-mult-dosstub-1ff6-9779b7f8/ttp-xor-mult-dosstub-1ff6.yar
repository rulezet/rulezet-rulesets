rule TTP_XOR_MULT_DOSStub_1ff6 {
  strings:
    $key_1ff6 = { 4b 9e [2] 3f 86 [2] 78 84 [2] 3f 95 [2] 71 99 [2] 7d 93 [2] 6a 98 [2] 71 d6 [2] 4c }

  condition:
    any of them
}