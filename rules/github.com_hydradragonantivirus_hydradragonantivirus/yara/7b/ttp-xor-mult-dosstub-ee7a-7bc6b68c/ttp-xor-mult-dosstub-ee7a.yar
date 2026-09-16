rule TTP_XOR_MULT_DOSStub_ee7a {
  strings:
    $key_ee7a = { ba 12 [2] ce 0a [2] 89 08 [2] ce 19 [2] 80 15 [2] 8c 1f [2] 9b 14 [2] 80 5a [2] bd }

  condition:
    any of them
}