rule TTP_XOR_MULT_DOSStub_1b69 {
  strings:
    $key_1b69 = { 4f 01 [2] 3b 19 [2] 7c 1b [2] 3b 0a [2] 75 06 [2] 79 0c [2] 6e 07 [2] 75 49 [2] 48 }

  condition:
    any of them
}