rule TTP_XOR_MULT_DOSStub_e9e1 {
  strings:
    $key_e9e1 = { bd 89 [2] c9 91 [2] 8e 93 [2] c9 82 [2] 87 8e [2] 8b 84 [2] 9c 8f [2] 87 c1 [2] ba }

  condition:
    any of them
}