rule TTP_XOR_MULT_DOSStub_32fa {
  strings:
    $key_32fa = { 66 92 [2] 12 8a [2] 55 88 [2] 12 99 [2] 5c 95 [2] 50 9f [2] 47 94 [2] 5c da [2] 61 }

  condition:
    any of them
}