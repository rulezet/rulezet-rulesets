rule TTP_XOR_MULT_DOSStub_675d {
  strings:
    $key_675d = { 33 35 [2] 47 2d [2] 00 2f [2] 47 3e [2] 09 32 [2] 05 38 [2] 12 33 [2] 09 7d [2] 34 }

  condition:
    any of them
}