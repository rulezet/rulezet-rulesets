rule TTP_XOR_MULT_DOSStub_2be8 {
  strings:
    $key_2be8 = { 7f 80 [2] 0b 98 [2] 4c 9a [2] 0b 8b [2] 45 87 [2] 49 8d [2] 5e 86 [2] 45 c8 [2] 78 }

  condition:
    any of them
}