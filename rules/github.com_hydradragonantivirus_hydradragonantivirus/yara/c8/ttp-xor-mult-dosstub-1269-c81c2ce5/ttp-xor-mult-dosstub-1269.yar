rule TTP_XOR_MULT_DOSStub_1269 {
  strings:
    $key_1269 = { 46 01 [2] 32 19 [2] 75 1b [2] 32 0a [2] 7c 06 [2] 70 0c [2] 67 07 [2] 7c 49 [2] 41 }

  condition:
    any of them
}