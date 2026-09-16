rule TTP_XOR_MULT_DOSStub_e90d {
  strings:
    $key_e90d = { bd 65 [2] c9 7d [2] 8e 7f [2] c9 6e [2] 87 62 [2] 8b 68 [2] 9c 63 [2] 87 2d [2] ba }

  condition:
    any of them
}