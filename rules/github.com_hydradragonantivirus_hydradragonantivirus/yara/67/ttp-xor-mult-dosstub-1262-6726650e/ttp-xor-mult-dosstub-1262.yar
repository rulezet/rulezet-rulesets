rule TTP_XOR_MULT_DOSStub_1262 {
  strings:
    $key_1262 = { 46 0a [2] 32 12 [2] 75 10 [2] 32 01 [2] 7c 0d [2] 70 07 [2] 67 0c [2] 7c 42 [2] 41 }

  condition:
    any of them
}