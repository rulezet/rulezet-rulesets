rule TTP_XOR_MULT_DOSStub_363f {
  strings:
    $key_363f = { 62 57 [2] 16 4f [2] 51 4d [2] 16 5c [2] 58 50 [2] 54 5a [2] 43 51 [2] 58 1f [2] 65 }

  condition:
    any of them
}