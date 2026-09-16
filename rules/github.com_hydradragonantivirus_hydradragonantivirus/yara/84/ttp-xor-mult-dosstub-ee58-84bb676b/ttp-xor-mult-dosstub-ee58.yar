rule TTP_XOR_MULT_DOSStub_ee58 {
  strings:
    $key_ee58 = { ba 30 [2] ce 28 [2] 89 2a [2] ce 3b [2] 80 37 [2] 8c 3d [2] 9b 36 [2] 80 78 [2] bd }

  condition:
    any of them
}