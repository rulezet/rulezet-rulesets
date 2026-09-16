rule TTP_XOR_MULT_DOSStub_ee79 {
  strings:
    $key_ee79 = { ba 11 [2] ce 09 [2] 89 0b [2] ce 1a [2] 80 16 [2] 8c 1c [2] 9b 17 [2] 80 59 [2] bd }

  condition:
    any of them
}