rule TTP_XOR_MULT_DOSStub_ee37 {
  strings:
    $key_ee37 = { ba 5f [2] ce 47 [2] 89 45 [2] ce 54 [2] 80 58 [2] 8c 52 [2] 9b 59 [2] 80 17 [2] bd }

  condition:
    any of them
}