rule TTP_XOR_MULT_DOSStub_5755 {
  strings:
    $key_5755 = { 03 3d [2] 77 25 [2] 30 27 [2] 77 36 [2] 39 3a [2] 35 30 [2] 22 3b [2] 39 75 [2] 04 }

  condition:
    any of them
}