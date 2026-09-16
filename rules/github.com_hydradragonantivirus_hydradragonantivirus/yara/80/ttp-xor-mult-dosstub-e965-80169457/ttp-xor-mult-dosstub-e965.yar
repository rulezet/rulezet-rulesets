rule TTP_XOR_MULT_DOSStub_e965 {
  strings:
    $key_e965 = { bd 0d [2] c9 15 [2] 8e 17 [2] c9 06 [2] 87 0a [2] 8b 00 [2] 9c 0b [2] 87 45 [2] ba }

  condition:
    any of them
}