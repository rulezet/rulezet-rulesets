rule TTP_XOR_MULT_DOSStub_ee65 {
  strings:
    $key_ee65 = { ba 0d [2] ce 15 [2] 89 17 [2] ce 06 [2] 80 0a [2] 8c 00 [2] 9b 0b [2] 80 45 [2] bd }

  condition:
    any of them
}