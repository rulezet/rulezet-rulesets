rule TTP_XOR_MULT_DOSStub_1b22 {
  strings:
    $key_1b22 = { 4f 4a [2] 3b 52 [2] 7c 50 [2] 3b 41 [2] 75 4d [2] 79 47 [2] 6e 4c [2] 75 02 [2] 48 }

  condition:
    any of them
}