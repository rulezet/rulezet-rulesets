rule TTP_XOR_MULT_DOSStub_f4fa {
  strings:
    $key_f4fa = { a0 92 [2] d4 8a [2] 93 88 [2] d4 99 [2] 9a 95 [2] 96 9f [2] 81 94 [2] 9a da [2] a7 }

  condition:
    any of them
}