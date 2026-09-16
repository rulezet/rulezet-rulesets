rule TTP_XOR_MULT_DOSStub_e926 {
  strings:
    $key_e926 = { bd 4e [2] c9 56 [2] 8e 54 [2] c9 45 [2] 87 49 [2] 8b 43 [2] 9c 48 [2] 87 06 [2] ba }

  condition:
    any of them
}