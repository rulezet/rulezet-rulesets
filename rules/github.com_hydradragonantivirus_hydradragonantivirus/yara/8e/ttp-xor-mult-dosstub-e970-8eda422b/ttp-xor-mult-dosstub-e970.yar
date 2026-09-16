rule TTP_XOR_MULT_DOSStub_e970 {
  strings:
    $key_e970 = { bd 18 [2] c9 00 [2] 8e 02 [2] c9 13 [2] 87 1f [2] 8b 15 [2] 9c 1e [2] 87 50 [2] ba }

  condition:
    any of them
}