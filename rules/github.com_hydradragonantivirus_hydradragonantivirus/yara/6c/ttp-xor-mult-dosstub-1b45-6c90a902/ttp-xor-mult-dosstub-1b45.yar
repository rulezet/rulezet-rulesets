rule TTP_XOR_MULT_DOSStub_1b45 {
  strings:
    $key_1b45 = { 4f 2d [2] 3b 35 [2] 7c 37 [2] 3b 26 [2] 75 2a [2] 79 20 [2] 6e 2b [2] 75 65 [2] 48 }

  condition:
    any of them
}