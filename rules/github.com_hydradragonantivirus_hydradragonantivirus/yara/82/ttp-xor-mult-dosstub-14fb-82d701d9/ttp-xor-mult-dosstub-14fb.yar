rule TTP_XOR_MULT_DOSStub_14fb {
  strings:
    $key_14fb = { 40 93 [2] 34 8b [2] 73 89 [2] 34 98 [2] 7a 94 [2] 76 9e [2] 61 95 [2] 7a db [2] 47 }

  condition:
    any of them
}