rule TTP_XOR_MULT_DOSStub_ee08 {
  strings:
    $key_ee08 = { ba 60 [2] ce 78 [2] 89 7a [2] ce 6b [2] 80 67 [2] 8c 6d [2] 9b 66 [2] 80 28 [2] bd }

  condition:
    any of them
}