rule TTP_XOR_MULT_DOSStub_a10a {
  strings:
    $key_a10a = { f5 62 [2] 81 7a [2] c6 78 [2] 81 69 [2] cf 65 [2] c3 6f [2] d4 64 [2] cf 2a [2] f2 }

  condition:
    any of them
}