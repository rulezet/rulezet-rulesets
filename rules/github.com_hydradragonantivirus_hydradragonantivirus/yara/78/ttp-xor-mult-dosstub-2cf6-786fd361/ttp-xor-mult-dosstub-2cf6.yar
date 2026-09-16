rule TTP_XOR_MULT_DOSStub_2cf6 {
  strings:
    $key_2cf6 = { 78 9e [2] 0c 86 [2] 4b 84 [2] 0c 95 [2] 42 99 [2] 4e 93 [2] 59 98 [2] 42 d6 [2] 7f }

  condition:
    any of them
}