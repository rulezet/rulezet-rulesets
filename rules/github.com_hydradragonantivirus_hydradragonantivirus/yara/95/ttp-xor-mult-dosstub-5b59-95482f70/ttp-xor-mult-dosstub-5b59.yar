rule TTP_XOR_MULT_DOSStub_5b59 {
  strings:
    $key_5b59 = { 0f 31 [2] 7b 29 [2] 3c 2b [2] 7b 3a [2] 35 36 [2] 39 3c [2] 2e 37 [2] 35 79 [2] 08 }

  condition:
    any of them
}