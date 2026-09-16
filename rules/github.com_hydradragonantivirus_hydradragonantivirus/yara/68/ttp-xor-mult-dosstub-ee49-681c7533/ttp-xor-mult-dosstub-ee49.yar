rule TTP_XOR_MULT_DOSStub_ee49 {
  strings:
    $key_ee49 = { ba 21 [2] ce 39 [2] 89 3b [2] ce 2a [2] 80 26 [2] 8c 2c [2] 9b 27 [2] 80 69 [2] bd }

  condition:
    any of them
}