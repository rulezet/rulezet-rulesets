rule TTP_XOR_MULT_DOSStub_ee42 {
  strings:
    $key_ee42 = { ba 2a [2] ce 32 [2] 89 30 [2] ce 21 [2] 80 2d [2] 8c 27 [2] 9b 2c [2] 80 62 [2] bd }

  condition:
    any of them
}