rule TTP_XOR_MULT_DOSStub_65e8 {
  strings:
    $key_65e8 = { 31 80 [2] 45 98 [2] 02 9a [2] 45 8b [2] 0b 87 [2] 07 8d [2] 10 86 [2] 0b c8 [2] 36 }

  condition:
    any of them
}