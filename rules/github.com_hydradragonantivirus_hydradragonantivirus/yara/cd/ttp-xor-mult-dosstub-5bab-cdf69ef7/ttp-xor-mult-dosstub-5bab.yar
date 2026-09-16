rule TTP_XOR_MULT_DOSStub_5bab {
  strings:
    $key_5bab = { 0f c3 [2] 7b db [2] 3c d9 [2] 7b c8 [2] 35 c4 [2] 39 ce [2] 2e c5 [2] 35 8b [2] 08 }

  condition:
    any of them
}