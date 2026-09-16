rule TTP_XOR_MULT_DOSStub_1b39 {
  strings:
    $key_1b39 = { 4f 51 [2] 3b 49 [2] 7c 4b [2] 3b 5a [2] 75 56 [2] 79 5c [2] 6e 57 [2] 75 19 [2] 48 }

  condition:
    any of them
}