rule TTP_XOR_MULT_DOSStub_ee1a {
  strings:
    $key_ee1a = { ba 72 [2] ce 6a [2] 89 68 [2] ce 79 [2] 80 75 [2] 8c 7f [2] 9b 74 [2] 80 3a [2] bd }

  condition:
    any of them
}