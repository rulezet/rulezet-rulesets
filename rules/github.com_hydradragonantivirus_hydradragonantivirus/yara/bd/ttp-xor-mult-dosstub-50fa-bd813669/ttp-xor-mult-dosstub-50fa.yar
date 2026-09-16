rule TTP_XOR_MULT_DOSStub_50fa {
  strings:
    $key_50fa = { 04 92 [2] 70 8a [2] 37 88 [2] 70 99 [2] 3e 95 [2] 32 9f [2] 25 94 [2] 3e da [2] 03 }

  condition:
    any of them
}