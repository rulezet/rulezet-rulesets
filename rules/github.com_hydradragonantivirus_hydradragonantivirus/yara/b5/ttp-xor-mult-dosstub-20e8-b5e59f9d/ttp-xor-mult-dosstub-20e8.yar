rule TTP_XOR_MULT_DOSStub_20e8 {
  strings:
    $key_20e8 = { 74 80 [2] 00 98 [2] 47 9a [2] 00 8b [2] 4e 87 [2] 42 8d [2] 55 86 [2] 4e c8 [2] 73 }

  condition:
    any of them
}