rule TTP_XOR_MULT_DOSStub_ee2a {
  strings:
    $key_ee2a = { ba 42 [2] ce 5a [2] 89 58 [2] ce 49 [2] 80 45 [2] 8c 4f [2] 9b 44 [2] 80 0a [2] bd }

  condition:
    any of them
}