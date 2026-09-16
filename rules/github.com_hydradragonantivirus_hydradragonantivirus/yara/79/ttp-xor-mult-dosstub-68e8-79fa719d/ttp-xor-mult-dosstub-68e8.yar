rule TTP_XOR_MULT_DOSStub_68e8 {
  strings:
    $key_68e8 = { 3c 80 [2] 48 98 [2] 0f 9a [2] 48 8b [2] 06 87 [2] 0a 8d [2] 1d 86 [2] 06 c8 [2] 3b }

  condition:
    any of them
}