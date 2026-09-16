rule TTP_XOR_MULT_DOSStub_e93d {
  strings:
    $key_e93d = { bd 55 [2] c9 4d [2] 8e 4f [2] c9 5e [2] 87 52 [2] 8b 58 [2] 9c 53 [2] 87 1d [2] ba }

  condition:
    any of them
}