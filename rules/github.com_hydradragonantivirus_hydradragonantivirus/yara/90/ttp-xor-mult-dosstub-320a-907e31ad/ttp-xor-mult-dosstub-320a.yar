rule TTP_XOR_MULT_DOSStub_320a {
  strings:
    $key_320a = { 66 62 [2] 12 7a [2] 55 78 [2] 12 69 [2] 5c 65 [2] 50 6f [2] 47 64 [2] 5c 2a [2] 61 }

  condition:
    any of them
}