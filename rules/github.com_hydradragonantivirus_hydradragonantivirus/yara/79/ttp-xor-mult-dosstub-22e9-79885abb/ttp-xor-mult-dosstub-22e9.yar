rule TTP_XOR_MULT_DOSStub_22e9 {
  strings:
    $key_22e9 = { 76 81 [2] 02 99 [2] 45 9b [2] 02 8a [2] 4c 86 [2] 40 8c [2] 57 87 [2] 4c c9 [2] 71 }

  condition:
    any of them
}