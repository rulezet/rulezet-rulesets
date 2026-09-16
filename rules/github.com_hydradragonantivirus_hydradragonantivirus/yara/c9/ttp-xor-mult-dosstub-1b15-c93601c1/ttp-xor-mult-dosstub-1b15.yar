rule TTP_XOR_MULT_DOSStub_1b15 {
  strings:
    $key_1b15 = { 4f 7d [2] 3b 65 [2] 7c 67 [2] 3b 76 [2] 75 7a [2] 79 70 [2] 6e 7b [2] 75 35 [2] 48 }

  condition:
    any of them
}