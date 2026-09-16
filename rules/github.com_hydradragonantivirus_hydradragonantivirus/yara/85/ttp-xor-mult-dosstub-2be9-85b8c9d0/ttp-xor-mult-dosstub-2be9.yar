rule TTP_XOR_MULT_DOSStub_2be9 {
  strings:
    $key_2be9 = { 7f 81 [2] 0b 99 [2] 4c 9b [2] 0b 8a [2] 45 86 [2] 49 8c [2] 5e 87 [2] 45 c9 [2] 78 }

  condition:
    any of them
}