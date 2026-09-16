rule TTP_XOR_MULT_DOSStub_5218 {
  strings:
    $key_5218 = { 06 70 [2] 72 68 [2] 35 6a [2] 72 7b [2] 3c 77 [2] 30 7d [2] 27 76 [2] 3c 38 [2] 01 }

  condition:
    any of them
}