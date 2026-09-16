rule TTP_XOR_MULT_DOSStub_160a {
  strings:
    $key_160a = { 42 62 [2] 36 7a [2] 71 78 [2] 36 69 [2] 78 65 [2] 74 6f [2] 63 64 [2] 78 2a [2] 45 }

  condition:
    any of them
}