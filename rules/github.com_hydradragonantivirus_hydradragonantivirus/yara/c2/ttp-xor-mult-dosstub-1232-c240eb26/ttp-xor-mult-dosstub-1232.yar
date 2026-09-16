rule TTP_XOR_MULT_DOSStub_1232 {
  strings:
    $key_1232 = { 46 5a [2] 32 42 [2] 75 40 [2] 32 51 [2] 7c 5d [2] 70 57 [2] 67 5c [2] 7c 12 [2] 41 }

  condition:
    any of them
}