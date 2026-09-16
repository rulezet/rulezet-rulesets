rule TTP_XOR_MULT_DOSStub_e9fa {
  strings:
    $key_e9fa = { bd 92 [2] c9 8a [2] 8e 88 [2] c9 99 [2] 87 95 [2] 8b 9f [2] 9c 94 [2] 87 da [2] ba }

  condition:
    any of them
}