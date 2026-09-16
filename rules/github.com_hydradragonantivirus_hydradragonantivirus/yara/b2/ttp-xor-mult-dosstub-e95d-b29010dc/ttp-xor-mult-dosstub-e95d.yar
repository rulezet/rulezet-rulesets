rule TTP_XOR_MULT_DOSStub_e95d {
  strings:
    $key_e95d = { bd 35 [2] c9 2d [2] 8e 2f [2] c9 3e [2] 87 32 [2] 8b 38 [2] 9c 33 [2] 87 7d [2] ba }

  condition:
    any of them
}