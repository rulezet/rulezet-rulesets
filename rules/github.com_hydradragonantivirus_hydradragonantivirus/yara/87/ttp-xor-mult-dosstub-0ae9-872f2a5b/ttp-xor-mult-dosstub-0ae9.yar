rule TTP_XOR_MULT_DOSStub_0ae9 {
  strings:
    $key_0ae9 = { 5e 81 [2] 2a 99 [2] 6d 9b [2] 2a 8a [2] 64 86 [2] 68 8c [2] 7f 87 [2] 64 c9 [2] 59 }

  condition:
    any of them
}