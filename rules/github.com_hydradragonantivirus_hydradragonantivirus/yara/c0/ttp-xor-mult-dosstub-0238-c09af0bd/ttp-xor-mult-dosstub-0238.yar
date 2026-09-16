rule TTP_XOR_MULT_DOSStub_0238 {
  strings:
    $key_0238 = { 56 50 [2] 22 48 [2] 65 4a [2] 22 5b [2] 6c 57 [2] 60 5d [2] 77 56 [2] 6c 18 [2] 51 }

  condition:
    any of them
}