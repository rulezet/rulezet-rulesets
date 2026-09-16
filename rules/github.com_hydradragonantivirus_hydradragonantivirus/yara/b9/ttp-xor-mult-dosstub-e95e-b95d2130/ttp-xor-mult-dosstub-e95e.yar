rule TTP_XOR_MULT_DOSStub_e95e {
  strings:
    $key_e95e = { bd 36 [2] c9 2e [2] 8e 2c [2] c9 3d [2] 87 31 [2] 8b 3b [2] 9c 30 [2] 87 7e [2] ba }

  condition:
    any of them
}