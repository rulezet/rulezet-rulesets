rule TTP_XOR_MULT_DOSStub_e9f6 {
  strings:
    $key_e9f6 = { bd 9e [2] c9 86 [2] 8e 84 [2] c9 95 [2] 87 99 [2] 8b 93 [2] 9c 98 [2] 87 d6 [2] ba }

  condition:
    any of them
}