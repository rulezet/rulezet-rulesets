rule TTP_XOR_MULT_DOSStub_3b09 {
  strings:
    $key_3b09 = { 6f 61 [2] 1b 79 [2] 5c 7b [2] 1b 6a [2] 55 66 [2] 59 6c [2] 4e 67 [2] 55 29 [2] 68 }

  condition:
    any of them
}