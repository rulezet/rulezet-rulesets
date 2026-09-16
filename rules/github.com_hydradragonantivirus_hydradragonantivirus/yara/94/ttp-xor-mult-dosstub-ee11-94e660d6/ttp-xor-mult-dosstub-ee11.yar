rule TTP_XOR_MULT_DOSStub_ee11 {
  strings:
    $key_ee11 = { ba 79 [2] ce 61 [2] 89 63 [2] ce 72 [2] 80 7e [2] 8c 74 [2] 9b 7f [2] 80 31 [2] bd }

  condition:
    any of them
}