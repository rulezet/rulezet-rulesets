rule TTP_XOR_MULT_DOSStub_1219 {
  strings:
    $key_1219 = { 46 71 [2] 32 69 [2] 75 6b [2] 32 7a [2] 7c 76 [2] 70 7c [2] 67 77 [2] 7c 39 [2] 41 }

  condition:
    any of them
}