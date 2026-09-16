rule TTP_XOR_MULT_DOSStub_3218 {
  strings:
    $key_3218 = { 66 70 [2] 12 68 [2] 55 6a [2] 12 7b [2] 5c 77 [2] 50 7d [2] 47 76 [2] 5c 38 [2] 61 }

  condition:
    any of them
}