rule TTP_XOR_MULT_DOSStub_51fa {
  strings:
    $key_51fa = { 05 92 [2] 71 8a [2] 36 88 [2] 71 99 [2] 3f 95 [2] 33 9f [2] 24 94 [2] 3f da [2] 02 }

  condition:
    any of them
}