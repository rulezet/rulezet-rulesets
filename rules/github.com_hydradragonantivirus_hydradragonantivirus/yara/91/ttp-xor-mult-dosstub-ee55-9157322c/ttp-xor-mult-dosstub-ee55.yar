rule TTP_XOR_MULT_DOSStub_ee55 {
  strings:
    $key_ee55 = { ba 3d [2] ce 25 [2] 89 27 [2] ce 36 [2] 80 3a [2] 8c 30 [2] 9b 3b [2] 80 75 [2] bd }

  condition:
    any of them
}