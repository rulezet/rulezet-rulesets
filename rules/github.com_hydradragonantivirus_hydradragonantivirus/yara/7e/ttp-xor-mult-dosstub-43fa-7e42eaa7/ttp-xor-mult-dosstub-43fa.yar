rule TTP_XOR_MULT_DOSStub_43fa {
  strings:
    $key_43fa = { 17 92 [2] 63 8a [2] 24 88 [2] 63 99 [2] 2d 95 [2] 21 9f [2] 36 94 [2] 2d da [2] 10 }

  condition:
    any of them
}