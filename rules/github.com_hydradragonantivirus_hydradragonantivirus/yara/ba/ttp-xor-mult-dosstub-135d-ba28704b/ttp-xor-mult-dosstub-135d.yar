rule TTP_XOR_MULT_DOSStub_135d {
  strings:
    $key_135d = { 47 35 [2] 33 2d [2] 74 2f [2] 33 3e [2] 7d 32 [2] 71 38 [2] 66 33 [2] 7d 7d [2] 40 }

  condition:
    any of them
}