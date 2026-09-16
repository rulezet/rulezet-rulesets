rule TTP_XOR_MULT_DOSStub_ee50 {
  strings:
    $key_ee50 = { ba 38 [2] ce 20 [2] 89 22 [2] ce 33 [2] 80 3f [2] 8c 35 [2] 9b 3e [2] 80 70 [2] bd }

  condition:
    any of them
}