rule TTP_XOR_MULT_DOSStub_3238 {
  strings:
    $key_3238 = { 66 50 [2] 12 48 [2] 55 4a [2] 12 5b [2] 5c 57 [2] 50 5d [2] 47 56 [2] 5c 18 [2] 61 }

  condition:
    any of them
}