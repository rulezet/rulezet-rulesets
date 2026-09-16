rule TTP_XOR_MULT_DOSStub_27fb {
  strings:
    $key_27fb = { 73 93 [2] 07 8b [2] 40 89 [2] 07 98 [2] 49 94 [2] 45 9e [2] 52 95 [2] 49 db [2] 74 }

  condition:
    any of them
}