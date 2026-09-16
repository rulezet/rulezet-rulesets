rule TTP_XOR_MULT_DOSStub_e956 {
  strings:
    $key_e956 = { bd 3e [2] c9 26 [2] 8e 24 [2] c9 35 [2] 87 39 [2] 8b 33 [2] 9c 38 [2] 87 76 [2] ba }

  condition:
    any of them
}