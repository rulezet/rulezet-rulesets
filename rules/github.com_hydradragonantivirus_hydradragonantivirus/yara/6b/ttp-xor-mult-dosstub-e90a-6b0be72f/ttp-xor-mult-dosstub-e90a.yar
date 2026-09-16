rule TTP_XOR_MULT_DOSStub_e90a {
  strings:
    $key_e90a = { bd 62 [2] c9 7a [2] 8e 78 [2] c9 69 [2] 87 65 [2] 8b 6f [2] 9c 64 [2] 87 2a [2] ba }

  condition:
    any of them
}