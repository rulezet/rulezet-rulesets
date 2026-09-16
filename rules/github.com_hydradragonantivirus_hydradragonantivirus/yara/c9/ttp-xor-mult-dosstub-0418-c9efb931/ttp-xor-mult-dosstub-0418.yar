rule TTP_XOR_MULT_DOSStub_0418 {
  strings:
    $key_0418 = { 50 70 [2] 24 68 [2] 63 6a [2] 24 7b [2] 6a 77 [2] 66 7d [2] 71 76 [2] 6a 38 [2] 57 }

  condition:
    any of them
}