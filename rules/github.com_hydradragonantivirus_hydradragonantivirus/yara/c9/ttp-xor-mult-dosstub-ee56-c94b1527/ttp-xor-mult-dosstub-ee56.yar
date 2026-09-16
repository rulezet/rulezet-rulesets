rule TTP_XOR_MULT_DOSStub_ee56 {
  strings:
    $key_ee56 = { ba 3e [2] ce 26 [2] 89 24 [2] ce 35 [2] 80 39 [2] 8c 33 [2] 9b 38 [2] 80 76 [2] bd }

  condition:
    any of them
}