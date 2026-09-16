rule TTP_XOR_MULT_DOSStub_66fb {
  strings:
    $key_66fb = { 32 93 [2] 46 8b [2] 01 89 [2] 46 98 [2] 08 94 [2] 04 9e [2] 13 95 [2] 08 db [2] 35 }

  condition:
    any of them
}