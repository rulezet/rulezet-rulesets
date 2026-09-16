rule TTP_XOR_MULT_DOSStub_29aa {
  strings:
    $key_29aa = { 7d c2 [2] 09 da [2] 4e d8 [2] 09 c9 [2] 47 c5 [2] 4b cf [2] 5c c4 [2] 47 8a [2] 7a }

  condition:
    any of them
}