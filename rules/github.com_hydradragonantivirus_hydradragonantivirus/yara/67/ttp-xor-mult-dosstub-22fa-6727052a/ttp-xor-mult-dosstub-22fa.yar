rule TTP_XOR_MULT_DOSStub_22fa {
  strings:
    $key_22fa = { 76 92 [2] 02 8a [2] 45 88 [2] 02 99 [2] 4c 95 [2] 40 9f [2] 57 94 [2] 4c da [2] 71 }

  condition:
    any of them
}