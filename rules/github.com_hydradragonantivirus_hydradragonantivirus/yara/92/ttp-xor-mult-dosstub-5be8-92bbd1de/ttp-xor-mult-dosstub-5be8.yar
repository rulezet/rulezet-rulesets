rule TTP_XOR_MULT_DOSStub_5be8 {
  strings:
    $key_5be8 = { 0f 80 [2] 7b 98 [2] 3c 9a [2] 7b 8b [2] 35 87 [2] 39 8d [2] 2e 86 [2] 35 c8 [2] 08 }

  condition:
    any of them
}