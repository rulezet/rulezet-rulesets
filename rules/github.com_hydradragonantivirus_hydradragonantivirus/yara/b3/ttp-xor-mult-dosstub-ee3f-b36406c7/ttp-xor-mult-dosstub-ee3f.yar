rule TTP_XOR_MULT_DOSStub_ee3f {
  strings:
    $key_ee3f = { ba 57 [2] ce 4f [2] 89 4d [2] ce 5c [2] 80 50 [2] 8c 5a [2] 9b 51 [2] 80 1f [2] bd }

  condition:
    any of them
}