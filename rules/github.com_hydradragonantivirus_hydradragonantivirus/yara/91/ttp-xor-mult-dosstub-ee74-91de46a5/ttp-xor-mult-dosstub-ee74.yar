rule TTP_XOR_MULT_DOSStub_ee74 {
  strings:
    $key_ee74 = { ba 1c [2] ce 04 [2] 89 06 [2] ce 17 [2] 80 1b [2] 8c 11 [2] 9b 1a [2] 80 54 [2] bd }

  condition:
    any of them
}