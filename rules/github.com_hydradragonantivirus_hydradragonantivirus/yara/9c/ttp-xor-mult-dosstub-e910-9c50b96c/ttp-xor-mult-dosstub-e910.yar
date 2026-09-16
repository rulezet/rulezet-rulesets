rule TTP_XOR_MULT_DOSStub_e910 {
  strings:
    $key_e910 = { bd 78 [2] c9 60 [2] 8e 62 [2] c9 73 [2] 87 7f [2] 8b 75 [2] 9c 7e [2] 87 30 [2] ba }

  condition:
    any of them
}