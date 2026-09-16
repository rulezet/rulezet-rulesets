rule TTP_XOR_MULT_DOSStub_7b59 {
  strings:
    $key_7b59 = { 2f 31 [2] 5b 29 [2] 1c 2b [2] 5b 3a [2] 15 36 [2] 19 3c [2] 0e 37 [2] 15 79 [2] 28 }

  condition:
    any of them
}