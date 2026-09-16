rule TTP_XOR_MULT_DOSStub_1b03 {
  strings:
    $key_1b03 = { 4f 6b [2] 3b 73 [2] 7c 71 [2] 3b 60 [2] 75 6c [2] 79 66 [2] 6e 6d [2] 75 23 [2] 48 }

  condition:
    any of them
}