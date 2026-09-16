rule TTP_XOR_MULT_DOSStub_5038 {
  strings:
    $key_5038 = { 04 50 [2] 70 48 [2] 37 4a [2] 70 5b [2] 3e 57 [2] 32 5d [2] 25 56 [2] 3e 18 [2] 03 }

  condition:
    any of them
}