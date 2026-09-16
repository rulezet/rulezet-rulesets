rule TTP_XOR_MULT_DOSStub_e9e4 {
  strings:
    $key_e9e4 = { bd 8c [2] c9 94 [2] 8e 96 [2] c9 87 [2] 87 8b [2] 8b 81 [2] 9c 8a [2] 87 c4 [2] ba }

  condition:
    any of them
}