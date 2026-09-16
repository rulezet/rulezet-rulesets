rule TTP_XOR_MULT_DOSStub_ee47 {
  strings:
    $key_ee47 = { ba 2f [2] ce 37 [2] 89 35 [2] ce 24 [2] 80 28 [2] 8c 22 [2] 9b 29 [2] 80 67 [2] bd }

  condition:
    any of them
}