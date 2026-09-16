rule TTP_XOR_MULT_DOSStub_24fb {
  strings:
    $key_24fb = { 70 93 [2] 04 8b [2] 43 89 [2] 04 98 [2] 4a 94 [2] 46 9e [2] 51 95 [2] 4a db [2] 77 }

  condition:
    any of them
}