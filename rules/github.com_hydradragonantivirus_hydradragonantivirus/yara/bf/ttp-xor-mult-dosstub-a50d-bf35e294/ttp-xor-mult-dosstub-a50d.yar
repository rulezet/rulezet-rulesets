rule TTP_XOR_MULT_DOSStub_a50d {
  strings:
    $key_a50d = { f1 65 [2] 85 7d [2] c2 7f [2] 85 6e [2] cb 62 [2] c7 68 [2] d0 63 [2] cb 2d [2] f6 }

  condition:
    any of them
}