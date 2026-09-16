rule TTP_XOR_MULT_DOSStub_e95a {
  strings:
    $key_e95a = { bd 32 [2] c9 2a [2] 8e 28 [2] c9 39 [2] 87 35 [2] 8b 3f [2] 9c 34 [2] 87 7a [2] ba }

  condition:
    any of them
}