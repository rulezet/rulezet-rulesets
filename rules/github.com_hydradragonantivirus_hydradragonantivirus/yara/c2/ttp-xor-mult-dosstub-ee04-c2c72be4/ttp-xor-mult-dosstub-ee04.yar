rule TTP_XOR_MULT_DOSStub_ee04 {
  strings:
    $key_ee04 = { ba 6c [2] ce 74 [2] 89 76 [2] ce 67 [2] 80 6b [2] 8c 61 [2] 9b 6a [2] 80 24 [2] bd }

  condition:
    any of them
}