rule TTP_XOR_MULT_DOSStub_1b33 {
  strings:
    $key_1b33 = { 4f 5b [2] 3b 43 [2] 7c 41 [2] 3b 50 [2] 75 5c [2] 79 56 [2] 6e 5d [2] 75 13 [2] 48 }

  condition:
    any of them
}