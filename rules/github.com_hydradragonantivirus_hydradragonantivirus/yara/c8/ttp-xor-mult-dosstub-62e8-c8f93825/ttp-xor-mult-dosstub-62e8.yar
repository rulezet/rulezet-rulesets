rule TTP_XOR_MULT_DOSStub_62e8 {
  strings:
    $key_62e8 = { 36 80 [2] 42 98 [2] 05 9a [2] 42 8b [2] 0c 87 [2] 00 8d [2] 17 86 [2] 0c c8 [2] 31 }

  condition:
    any of them
}