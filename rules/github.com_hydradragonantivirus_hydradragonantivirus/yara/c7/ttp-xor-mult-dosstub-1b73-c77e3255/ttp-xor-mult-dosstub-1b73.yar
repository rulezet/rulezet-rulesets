rule TTP_XOR_MULT_DOSStub_1b73 {
  strings:
    $key_1b73 = { 4f 1b [2] 3b 03 [2] 7c 01 [2] 3b 10 [2] 75 1c [2] 79 16 [2] 6e 1d [2] 75 53 [2] 48 }

  condition:
    any of them
}