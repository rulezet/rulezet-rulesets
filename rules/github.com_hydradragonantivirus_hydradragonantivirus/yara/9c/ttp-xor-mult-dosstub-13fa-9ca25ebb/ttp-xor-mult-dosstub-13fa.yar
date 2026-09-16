rule TTP_XOR_MULT_DOSStub_13fa {
  strings:
    $key_13fa = { 47 92 [2] 33 8a [2] 74 88 [2] 33 99 [2] 7d 95 [2] 71 9f [2] 66 94 [2] 7d da [2] 40 }

  condition:
    any of them
}