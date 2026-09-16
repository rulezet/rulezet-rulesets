rule TTP_XOR_MULT_DOSStub_22e8 {
  strings:
    $key_22e8 = { 76 80 [2] 02 98 [2] 45 9a [2] 02 8b [2] 4c 87 [2] 40 8d [2] 57 86 [2] 4c c8 [2] 71 }

  condition:
    any of them
}