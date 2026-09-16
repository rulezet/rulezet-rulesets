rule TTP_XOR_MULT_DOSStub_2b54 {
  strings:
    $key_2b54 = { 7f 3c [2] 0b 24 [2] 4c 26 [2] 0b 37 [2] 45 3b [2] 49 31 [2] 5e 3a [2] 45 74 [2] 78 }

  condition:
    any of them
}