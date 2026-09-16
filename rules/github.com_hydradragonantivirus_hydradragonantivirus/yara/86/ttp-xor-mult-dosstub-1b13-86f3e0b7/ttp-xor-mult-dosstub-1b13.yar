rule TTP_XOR_MULT_DOSStub_1b13 {
  strings:
    $key_1b13 = { 4f 7b [2] 3b 63 [2] 7c 61 [2] 3b 70 [2] 75 7c [2] 79 76 [2] 6e 7d [2] 75 33 [2] 48 }

  condition:
    any of them
}