rule TTP_XOR_MULT_DOSStub_ee15 {
  strings:
    $key_ee15 = { ba 7d [2] ce 65 [2] 89 67 [2] ce 76 [2] 80 7a [2] 8c 70 [2] 9b 7b [2] 80 35 [2] bd }

  condition:
    any of them
}