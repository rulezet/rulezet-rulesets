rule TTP_XOR_MULT_DOSStub_ee39 {
  strings:
    $key_ee39 = { ba 51 [2] ce 49 [2] 89 4b [2] ce 5a [2] 80 56 [2] 8c 5c [2] 9b 57 [2] 80 19 [2] bd }

  condition:
    any of them
}