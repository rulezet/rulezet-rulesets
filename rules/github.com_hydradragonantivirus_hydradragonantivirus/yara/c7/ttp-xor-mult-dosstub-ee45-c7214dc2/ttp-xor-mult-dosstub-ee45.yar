rule TTP_XOR_MULT_DOSStub_ee45 {
  strings:
    $key_ee45 = { ba 2d [2] ce 35 [2] 89 37 [2] ce 26 [2] 80 2a [2] 8c 20 [2] 9b 2b [2] 80 65 [2] bd }

  condition:
    any of them
}