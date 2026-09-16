rule TTP_XOR_MULT_DOSStub_ee12 {
  strings:
    $key_ee12 = { ba 7a [2] ce 62 [2] 89 60 [2] ce 71 [2] 80 7d [2] 8c 77 [2] 9b 7c [2] 80 32 [2] bd }

  condition:
    any of them
}