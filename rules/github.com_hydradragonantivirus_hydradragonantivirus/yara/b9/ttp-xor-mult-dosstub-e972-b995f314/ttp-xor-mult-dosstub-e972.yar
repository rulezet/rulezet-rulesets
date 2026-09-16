rule TTP_XOR_MULT_DOSStub_e972 {
  strings:
    $key_e972 = { bd 1a [2] c9 02 [2] 8e 00 [2] c9 11 [2] 87 1d [2] 8b 17 [2] 9c 1c [2] 87 52 [2] ba }

  condition:
    any of them
}