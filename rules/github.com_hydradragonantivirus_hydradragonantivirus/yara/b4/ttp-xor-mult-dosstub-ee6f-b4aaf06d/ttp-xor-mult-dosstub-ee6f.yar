rule TTP_XOR_MULT_DOSStub_ee6f {
  strings:
    $key_ee6f = { ba 07 [2] ce 1f [2] 89 1d [2] ce 0c [2] 80 00 [2] 8c 0a [2] 9b 01 [2] 80 4f [2] bd }

  condition:
    any of them
}