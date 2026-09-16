rule TTP_XOR_MULT_DOSStub_e9f7 {
  strings:
    $key_e9f7 = { bd 9f [2] c9 87 [2] 8e 85 [2] c9 94 [2] 87 98 [2] 8b 92 [2] 9c 99 [2] 87 d7 [2] ba }

  condition:
    any of them
}