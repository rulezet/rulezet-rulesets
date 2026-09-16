rule TTP_XOR_MULT_DOSStub_ee28 {
  strings:
    $key_ee28 = { ba 40 [2] ce 58 [2] 89 5a [2] ce 4b [2] 80 47 [2] 8c 4d [2] 9b 46 [2] 80 08 [2] bd }

  condition:
    any of them
}