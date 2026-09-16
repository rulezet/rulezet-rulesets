rule TTP_XOR_MULT_DOSStub_0038 {
  strings:
    $key_0038 = { 54 50 [2] 20 48 [2] 67 4a [2] 20 5b [2] 6e 57 [2] 62 5d [2] 75 56 [2] 6e 18 [2] 53 }

  condition:
    any of them
}