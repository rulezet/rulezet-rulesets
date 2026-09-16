rule TTP_XOR_MULT_DOSStub_0738 {
  strings:
    $key_0738 = { 53 50 [2] 27 48 [2] 60 4a [2] 27 5b [2] 69 57 [2] 65 5d [2] 72 56 [2] 69 18 [2] 54 }

  condition:
    any of them
}