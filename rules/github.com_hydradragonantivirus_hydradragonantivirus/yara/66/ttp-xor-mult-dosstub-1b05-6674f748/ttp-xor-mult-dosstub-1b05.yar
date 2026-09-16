rule TTP_XOR_MULT_DOSStub_1b05 {
  strings:
    $key_1b05 = { 4f 6d [2] 3b 75 [2] 7c 77 [2] 3b 66 [2] 75 6a [2] 79 60 [2] 6e 6b [2] 75 25 [2] 48 }

  condition:
    any of them
}