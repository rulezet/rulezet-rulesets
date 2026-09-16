rule TTP_XOR_MULT_DOSStub_e951 {
  strings:
    $key_e951 = { bd 39 [2] c9 21 [2] 8e 23 [2] c9 32 [2] 87 3e [2] 8b 34 [2] 9c 3f [2] 87 71 [2] ba }

  condition:
    any of them
}