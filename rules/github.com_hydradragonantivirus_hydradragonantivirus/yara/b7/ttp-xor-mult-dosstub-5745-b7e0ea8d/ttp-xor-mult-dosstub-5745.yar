rule TTP_XOR_MULT_DOSStub_5745 {
  strings:
    $key_5745 = { 03 2d [2] 77 35 [2] 30 37 [2] 77 26 [2] 39 2a [2] 35 20 [2] 22 2b [2] 39 65 [2] 04 }

  condition:
    any of them
}