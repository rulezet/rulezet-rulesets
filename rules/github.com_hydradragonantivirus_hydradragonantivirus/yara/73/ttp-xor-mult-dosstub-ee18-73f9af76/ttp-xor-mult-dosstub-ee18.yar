rule TTP_XOR_MULT_DOSStub_ee18 {
  strings:
    $key_ee18 = { ba 70 [2] ce 68 [2] 89 6a [2] ce 7b [2] 80 77 [2] 8c 7d [2] 9b 76 [2] 80 38 [2] bd }

  condition:
    any of them
}