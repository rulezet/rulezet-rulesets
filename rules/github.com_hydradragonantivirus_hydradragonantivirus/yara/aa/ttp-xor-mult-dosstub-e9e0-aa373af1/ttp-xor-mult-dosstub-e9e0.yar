rule TTP_XOR_MULT_DOSStub_e9e0 {
  strings:
    $key_e9e0 = { bd 88 [2] c9 90 [2] 8e 92 [2] c9 83 [2] 87 8f [2] 8b 85 [2] 9c 8e [2] 87 c0 [2] ba }

  condition:
    any of them
}