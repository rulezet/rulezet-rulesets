rule TTP_XOR_MULT_DOSStub_ee5a {
  strings:
    $key_ee5a = { ba 32 [2] ce 2a [2] 89 28 [2] ce 39 [2] 80 35 [2] 8c 3f [2] 9b 34 [2] 80 7a [2] bd }

  condition:
    any of them
}