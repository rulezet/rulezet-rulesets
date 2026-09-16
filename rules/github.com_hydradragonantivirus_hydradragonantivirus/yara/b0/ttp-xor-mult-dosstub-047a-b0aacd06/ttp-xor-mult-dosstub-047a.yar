rule TTP_XOR_MULT_DOSStub_047a {
  strings:
    $key_047a = { 50 12 [2] 24 0a [2] 63 08 [2] 24 19 [2] 6a 15 [2] 66 1f [2] 71 14 [2] 6a 5a [2] 57 }

  condition:
    any of them
}