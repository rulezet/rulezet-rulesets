rule TTP_XOR_MULT_DOSStub_eee2 {
  strings:
    $key_eee2 = { ba 8a [2] ce 92 [2] 89 90 [2] ce 81 [2] 80 8d [2] 8c 87 [2] 9b 8c [2] 80 c2 [2] bd }

  condition:
    any of them
}