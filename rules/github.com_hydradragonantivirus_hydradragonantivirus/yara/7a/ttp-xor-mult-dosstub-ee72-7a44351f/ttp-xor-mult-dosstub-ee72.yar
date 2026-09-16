rule TTP_XOR_MULT_DOSStub_ee72 {
  strings:
    $key_ee72 = { ba 1a [2] ce 02 [2] 89 00 [2] ce 11 [2] 80 1d [2] 8c 17 [2] 9b 1c [2] 80 52 [2] bd }

  condition:
    any of them
}