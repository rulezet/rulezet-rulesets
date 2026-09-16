rule TTP_XOR_MULT_DOSStub_4458 {
  strings:
    $key_4458 = { 10 30 [2] 64 28 [2] 23 2a [2] 64 3b [2] 2a 37 [2] 26 3d [2] 31 36 [2] 2a 78 [2] 17 }

  condition:
    any of them
}