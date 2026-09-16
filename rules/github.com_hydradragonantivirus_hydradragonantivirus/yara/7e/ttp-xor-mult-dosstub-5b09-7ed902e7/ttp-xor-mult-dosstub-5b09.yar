rule TTP_XOR_MULT_DOSStub_5b09 {
  strings:
    $key_5b09 = { 0f 61 [2] 7b 79 [2] 3c 7b [2] 7b 6a [2] 35 66 [2] 39 6c [2] 2e 67 [2] 35 29 [2] 08 }

  condition:
    any of them
}