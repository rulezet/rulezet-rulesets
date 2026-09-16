rule TTP_XOR_MULT_DOSStub_1851 {
  strings:
    $key_1851 = { 4c 39 [2] 38 21 [2] 7f 23 [2] 38 32 [2] 76 3e [2] 7a 34 [2] 6d 3f [2] 76 71 [2] 4b }

  condition:
    any of them
}