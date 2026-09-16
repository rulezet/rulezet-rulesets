rule TTP_XOR_MULT_DOSStub_ee4a {
  strings:
    $key_ee4a = { ba 22 [2] ce 3a [2] 89 38 [2] ce 29 [2] 80 25 [2] 8c 2f [2] 9b 24 [2] 80 6a [2] bd }

  condition:
    any of them
}