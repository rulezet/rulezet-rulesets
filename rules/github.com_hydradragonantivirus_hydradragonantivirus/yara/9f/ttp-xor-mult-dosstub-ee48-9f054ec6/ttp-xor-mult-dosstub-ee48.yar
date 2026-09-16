rule TTP_XOR_MULT_DOSStub_ee48 {
  strings:
    $key_ee48 = { ba 20 [2] ce 38 [2] 89 3a [2] ce 2b [2] 80 27 [2] 8c 2d [2] 9b 26 [2] 80 68 [2] bd }

  condition:
    any of them
}