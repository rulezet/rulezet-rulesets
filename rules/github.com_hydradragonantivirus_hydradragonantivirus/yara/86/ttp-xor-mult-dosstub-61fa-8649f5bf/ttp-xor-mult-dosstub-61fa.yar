rule TTP_XOR_MULT_DOSStub_61fa {
  strings:
    $key_61fa = { 35 92 [2] 41 8a [2] 06 88 [2] 41 99 [2] 0f 95 [2] 03 9f [2] 14 94 [2] 0f da [2] 32 }

  condition:
    any of them
}