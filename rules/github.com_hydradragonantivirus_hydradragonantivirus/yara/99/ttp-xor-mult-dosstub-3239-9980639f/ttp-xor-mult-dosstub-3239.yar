rule TTP_XOR_MULT_DOSStub_3239 {
  strings:
    $key_3239 = { 66 51 [2] 12 49 [2] 55 4b [2] 12 5a [2] 5c 56 [2] 50 5c [2] 47 57 [2] 5c 19 [2] 61 }

  condition:
    any of them
}