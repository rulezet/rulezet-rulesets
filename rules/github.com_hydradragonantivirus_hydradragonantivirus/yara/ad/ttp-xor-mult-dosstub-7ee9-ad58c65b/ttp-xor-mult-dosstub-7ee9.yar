rule TTP_XOR_MULT_DOSStub_7ee9 {
  strings:
    $key_7ee9 = { 2a 81 [2] 5e 99 [2] 19 9b [2] 5e 8a [2] 10 86 [2] 1c 8c [2] 0b 87 [2] 10 c9 [2] 2d }

  condition:
    any of them
}