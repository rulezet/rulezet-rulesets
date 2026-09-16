rule TTP_XOR_MULT_DOSStub_e925 {
  strings:
    $key_e925 = { bd 4d [2] c9 55 [2] 8e 57 [2] c9 46 [2] 87 4a [2] 8b 40 [2] 9c 4b [2] 87 05 [2] ba }

  condition:
    any of them
}