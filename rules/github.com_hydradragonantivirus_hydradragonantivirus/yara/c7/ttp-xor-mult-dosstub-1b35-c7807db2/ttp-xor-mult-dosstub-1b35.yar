rule TTP_XOR_MULT_DOSStub_1b35 {
  strings:
    $key_1b35 = { 4f 5d [2] 3b 45 [2] 7c 47 [2] 3b 56 [2] 75 5a [2] 79 50 [2] 6e 5b [2] 75 15 [2] 48 }

  condition:
    any of them
}