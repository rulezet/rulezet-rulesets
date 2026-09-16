rule TTP_XOR_MULT_DOSStub_ee09 {
  strings:
    $key_ee09 = { ba 61 [2] ce 79 [2] 89 7b [2] ce 6a [2] 80 66 [2] 8c 6c [2] 9b 67 [2] 80 29 [2] bd }

  condition:
    any of them
}