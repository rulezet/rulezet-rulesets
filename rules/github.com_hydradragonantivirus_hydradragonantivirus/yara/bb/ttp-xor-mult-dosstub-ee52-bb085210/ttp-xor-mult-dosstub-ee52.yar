rule TTP_XOR_MULT_DOSStub_ee52 {
  strings:
    $key_ee52 = { ba 3a [2] ce 22 [2] 89 20 [2] ce 31 [2] 80 3d [2] 8c 37 [2] 9b 3c [2] 80 72 [2] bd }

  condition:
    any of them
}