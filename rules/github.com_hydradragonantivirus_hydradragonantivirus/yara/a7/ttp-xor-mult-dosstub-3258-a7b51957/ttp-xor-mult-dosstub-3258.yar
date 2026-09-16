rule TTP_XOR_MULT_DOSStub_3258 {
  strings:
    $key_3258 = { 66 30 [2] 12 28 [2] 55 2a [2] 12 3b [2] 5c 37 [2] 50 3d [2] 47 36 [2] 5c 78 [2] 61 }

  condition:
    any of them
}