rule TTP_XOR_MULT_DOSStub_32e8 {
  strings:
    $key_32e8 = { 66 80 [2] 12 98 [2] 55 9a [2] 12 8b [2] 5c 87 [2] 50 8d [2] 47 86 [2] 5c c8 [2] 61 }

  condition:
    any of them
}