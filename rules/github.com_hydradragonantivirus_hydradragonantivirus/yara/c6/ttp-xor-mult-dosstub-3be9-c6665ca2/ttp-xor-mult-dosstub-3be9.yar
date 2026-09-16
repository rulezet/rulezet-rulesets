rule TTP_XOR_MULT_DOSStub_3be9 {
  strings:
    $key_3be9 = { 6f 81 [2] 1b 99 [2] 5c 9b [2] 1b 8a [2] 55 86 [2] 59 8c [2] 4e 87 [2] 55 c9 [2] 68 }

  condition:
    any of them
}