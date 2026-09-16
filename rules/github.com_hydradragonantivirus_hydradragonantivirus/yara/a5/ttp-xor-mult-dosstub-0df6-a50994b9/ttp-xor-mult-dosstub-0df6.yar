rule TTP_XOR_MULT_DOSStub_0df6 {
  strings:
    $key_0df6 = { 59 9e [2] 2d 86 [2] 6a 84 [2] 2d 95 [2] 63 99 [2] 6f 93 [2] 78 98 [2] 63 d6 [2] 5e }

  condition:
    any of them
}