rule TTP_XOR_MULT_DOSStub_e9e8 {
  strings:
    $key_e9e8 = { bd 80 [2] c9 98 [2] 8e 9a [2] c9 8b [2] 87 87 [2] 8b 8d [2] 9c 86 [2] 87 c8 [2] ba }

  condition:
    any of them
}