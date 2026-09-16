rule TTP_XOR_MULT_DOSStub_33fa {
  strings:
    $key_33fa = { 67 92 [2] 13 8a [2] 54 88 [2] 13 99 [2] 5d 95 [2] 51 9f [2] 46 94 [2] 5d da [2] 60 }

  condition:
    any of them
}