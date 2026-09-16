rule TTP_XOR_MULT_DOSStub_ee5d {
  strings:
    $key_ee5d = { ba 35 [2] ce 2d [2] 89 2f [2] ce 3e [2] 80 32 [2] 8c 38 [2] 9b 33 [2] 80 7d [2] bd }

  condition:
    any of them
}