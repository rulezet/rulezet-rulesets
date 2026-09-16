rule TTP_XOR_MULT_DOSStub_e9aa {
  strings:
    $key_e9aa = { bd c2 [2] c9 da [2] 8e d8 [2] c9 c9 [2] 87 c5 [2] 8b cf [2] 9c c4 [2] 87 8a [2] ba }

  condition:
    any of them
}