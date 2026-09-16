rule TTP_XOR_MULT_DOSStub_2b59 {
  strings:
    $key_2b59 = { 7f 31 [2] 0b 29 [2] 4c 2b [2] 0b 3a [2] 45 36 [2] 49 3c [2] 5e 37 [2] 45 79 [2] 78 }

  condition:
    any of them
}