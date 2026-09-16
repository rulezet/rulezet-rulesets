rule TTP_XOR_MULT_DOSStub_1202 {
  strings:
    $key_1202 = { 46 6a [2] 32 72 [2] 75 70 [2] 32 61 [2] 7c 6d [2] 70 67 [2] 67 6c [2] 7c 22 [2] 41 }

  condition:
    any of them
}