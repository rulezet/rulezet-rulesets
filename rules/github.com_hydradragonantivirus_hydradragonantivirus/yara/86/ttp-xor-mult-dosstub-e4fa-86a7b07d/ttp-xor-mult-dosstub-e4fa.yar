rule TTP_XOR_MULT_DOSStub_e4fa {
  strings:
    $key_e4fa = { b0 92 [2] c4 8a [2] 83 88 [2] c4 99 [2] 8a 95 [2] 86 9f [2] 91 94 [2] 8a da [2] b7 }

  condition:
    any of them
}