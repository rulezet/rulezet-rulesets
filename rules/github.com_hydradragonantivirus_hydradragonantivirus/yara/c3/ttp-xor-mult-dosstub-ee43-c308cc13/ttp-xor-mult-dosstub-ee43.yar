rule TTP_XOR_MULT_DOSStub_ee43 {
  strings:
    $key_ee43 = { ba 2b [2] ce 33 [2] 89 31 [2] ce 20 [2] 80 2c [2] 8c 26 [2] 9b 2d [2] 80 63 [2] bd }

  condition:
    any of them
}