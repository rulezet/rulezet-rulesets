rule TTP_XOR_MULT_DOSStub_0dfc {
  strings:
    $key_0dfc = { 59 94 [2] 2d 8c [2] 6a 8e [2] 2d 9f [2] 63 93 [2] 6f 99 [2] 78 92 [2] 63 dc [2] 5e }

  condition:
    any of them
}