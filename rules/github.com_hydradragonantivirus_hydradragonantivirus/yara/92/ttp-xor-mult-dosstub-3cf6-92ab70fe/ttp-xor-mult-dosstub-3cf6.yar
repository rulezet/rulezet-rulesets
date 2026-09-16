rule TTP_XOR_MULT_DOSStub_3cf6 {
  strings:
    $key_3cf6 = { 68 9e [2] 1c 86 [2] 5b 84 [2] 1c 95 [2] 52 99 [2] 5e 93 [2] 49 98 [2] 52 d6 [2] 6f }

  condition:
    any of them
}