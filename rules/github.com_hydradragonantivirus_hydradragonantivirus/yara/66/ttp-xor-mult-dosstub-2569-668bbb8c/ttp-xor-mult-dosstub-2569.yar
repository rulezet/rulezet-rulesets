rule TTP_XOR_MULT_DOSStub_2569 {
  strings:
    $key_2569 = { 71 01 [2] 05 19 [2] 42 1b [2] 05 0a [2] 4b 06 [2] 47 0c [2] 50 07 [2] 4b 49 [2] 76 }

  condition:
    any of them
}