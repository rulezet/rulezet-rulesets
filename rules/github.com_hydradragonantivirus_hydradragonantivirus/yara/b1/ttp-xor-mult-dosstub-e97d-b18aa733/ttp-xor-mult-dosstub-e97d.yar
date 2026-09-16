rule TTP_XOR_MULT_DOSStub_e97d {
  strings:
    $key_e97d = { bd 15 [2] c9 0d [2] 8e 0f [2] c9 1e [2] 87 12 [2] 8b 18 [2] 9c 13 [2] 87 5d [2] ba }

  condition:
    any of them
}