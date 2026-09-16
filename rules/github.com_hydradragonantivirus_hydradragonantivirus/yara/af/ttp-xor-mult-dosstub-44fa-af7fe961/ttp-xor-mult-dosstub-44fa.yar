rule TTP_XOR_MULT_DOSStub_44fa {
  strings:
    $key_44fa = { 10 92 [2] 64 8a [2] 23 88 [2] 64 99 [2] 2a 95 [2] 26 9f [2] 31 94 [2] 2a da [2] 17 }

  condition:
    any of them
}