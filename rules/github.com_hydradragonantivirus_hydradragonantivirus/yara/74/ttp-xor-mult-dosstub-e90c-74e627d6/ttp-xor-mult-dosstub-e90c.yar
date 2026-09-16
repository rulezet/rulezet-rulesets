rule TTP_XOR_MULT_DOSStub_e90c {
  strings:
    $key_e90c = { bd 64 [2] c9 7c [2] 8e 7e [2] c9 6f [2] 87 63 [2] 8b 69 [2] 9c 62 [2] 87 2c [2] ba }

  condition:
    any of them
}