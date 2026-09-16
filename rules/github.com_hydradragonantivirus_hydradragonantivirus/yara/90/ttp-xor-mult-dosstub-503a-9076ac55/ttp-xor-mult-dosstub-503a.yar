rule TTP_XOR_MULT_DOSStub_503a {
  strings:
    $key_503a = { 04 52 [2] 70 4a [2] 37 48 [2] 70 59 [2] 3e 55 [2] 32 5f [2] 25 54 [2] 3e 1a [2] 03 }

  condition:
    any of them
}