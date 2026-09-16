rule TTP_XOR_MULT_DOSStub_52e8 {
  strings:
    $key_52e8 = { 06 80 [2] 72 98 [2] 35 9a [2] 72 8b [2] 3c 87 [2] 30 8d [2] 27 86 [2] 3c c8 [2] 01 }

  condition:
    any of them
}