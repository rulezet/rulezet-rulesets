rule TTP_XOR_MULT_DOSStub_56fb {
  strings:
    $key_56fb = { 02 93 [2] 76 8b [2] 31 89 [2] 76 98 [2] 38 94 [2] 34 9e [2] 23 95 [2] 38 db [2] 05 }

  condition:
    any of them
}