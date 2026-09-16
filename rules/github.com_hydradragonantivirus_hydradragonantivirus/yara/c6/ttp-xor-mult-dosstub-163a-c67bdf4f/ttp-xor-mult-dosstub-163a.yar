rule TTP_XOR_MULT_DOSStub_163a {
  strings:
    $key_163a = { 42 52 [2] 36 4a [2] 71 48 [2] 36 59 [2] 78 55 [2] 74 5f [2] 63 54 [2] 78 1a [2] 45 }

  condition:
    any of them
}