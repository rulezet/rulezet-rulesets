rule TTP_XOR_MULT_DOSStub_26e8 {
  strings:
    $key_26e8 = { 72 80 [2] 06 98 [2] 41 9a [2] 06 8b [2] 48 87 [2] 44 8d [2] 53 86 [2] 48 c8 [2] 75 }

  condition:
    any of them
}