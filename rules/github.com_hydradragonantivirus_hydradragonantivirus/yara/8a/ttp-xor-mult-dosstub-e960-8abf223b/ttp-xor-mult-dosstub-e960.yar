rule TTP_XOR_MULT_DOSStub_e960 {
  strings:
    $key_e960 = { bd 08 [2] c9 10 [2] 8e 12 [2] c9 03 [2] 87 0f [2] 8b 05 [2] 9c 0e [2] 87 40 [2] ba }

  condition:
    any of them
}