rule TTP_XOR_MULT_DOSStub_2564 {
  strings:
    $key_2564 = { 71 0c [2] 05 14 [2] 42 16 [2] 05 07 [2] 4b 0b [2] 47 01 [2] 50 0a [2] 4b 44 [2] 76 }

  condition:
    any of them
}