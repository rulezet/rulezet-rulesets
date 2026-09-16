rule TTP_XOR_MULT_DOSStub_57fa {
  strings:
    $key_57fa = { 03 92 [2] 77 8a [2] 30 88 [2] 77 99 [2] 39 95 [2] 35 9f [2] 22 94 [2] 39 da [2] 04 }

  condition:
    any of them
}