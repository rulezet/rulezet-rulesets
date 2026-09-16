rule TTP_XOR_MULT_DOSStub_2ce9 {
  strings:
    $key_2ce9 = { 78 81 [2] 0c 99 [2] 4b 9b [2] 0c 8a [2] 42 86 [2] 4e 8c [2] 59 87 [2] 42 c9 [2] 7f }

  condition:
    any of them
}