rule TTP_XOR_MULT_DOSStub_7be8 {
  strings:
    $key_7be8 = { 2f 80 [2] 5b 98 [2] 1c 9a [2] 5b 8b [2] 15 87 [2] 19 8d [2] 0e 86 [2] 15 c8 [2] 28 }

  condition:
    any of them
}