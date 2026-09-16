rule TTP_XOR_MULT_DOSStub_363a {
  strings:
    $key_363a = { 62 52 [2] 16 4a [2] 51 48 [2] 16 59 [2] 58 55 [2] 54 5f [2] 43 54 [2] 58 1a [2] 65 }

  condition:
    any of them
}