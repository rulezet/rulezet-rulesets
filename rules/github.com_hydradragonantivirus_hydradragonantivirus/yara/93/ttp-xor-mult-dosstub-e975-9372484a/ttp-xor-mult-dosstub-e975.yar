rule TTP_XOR_MULT_DOSStub_e975 {
  strings:
    $key_e975 = { bd 1d [2] c9 05 [2] 8e 07 [2] c9 16 [2] 87 1a [2] 8b 10 [2] 9c 1b [2] 87 55 [2] ba }

  condition:
    any of them
}