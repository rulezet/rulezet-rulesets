rule TTP_XOR_MULT_DOSStub_22e7 {
  strings:
    $key_22e7 = { 76 8f [2] 02 97 [2] 45 95 [2] 02 84 [2] 4c 88 [2] 40 82 [2] 57 89 [2] 4c c7 [2] 71 }

  condition:
    any of them
}