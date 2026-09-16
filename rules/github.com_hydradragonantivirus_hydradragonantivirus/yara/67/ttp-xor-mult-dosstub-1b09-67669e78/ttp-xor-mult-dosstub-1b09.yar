rule TTP_XOR_MULT_DOSStub_1b09 {
  strings:
    $key_1b09 = { 4f 61 [2] 3b 79 [2] 7c 7b [2] 3b 6a [2] 75 66 [2] 79 6c [2] 6e 67 [2] 75 29 [2] 48 }

  condition:
    any of them
}