rule TTP_XOR_MULT_DOSStub_e920 {
  strings:
    $key_e920 = { bd 48 [2] c9 50 [2] 8e 52 [2] c9 43 [2] 87 4f [2] 8b 45 [2] 9c 4e [2] 87 00 [2] ba }

  condition:
    any of them
}