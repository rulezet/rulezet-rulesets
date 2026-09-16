rule TTP_XOR_MULT_DOSStub_5afb {
  strings:
    $key_5afb = { 0e 93 [2] 7a 8b [2] 3d 89 [2] 7a 98 [2] 34 94 [2] 38 9e [2] 2f 95 [2] 34 db [2] 09 }

  condition:
    any of them
}