rule TTP_XOR_MULT_DOSStub_e901 {
  strings:
    $key_e901 = { bd 69 [2] c9 71 [2] 8e 73 [2] c9 62 [2] 87 6e [2] 8b 64 [2] 9c 6f [2] 87 21 [2] ba }

  condition:
    any of them
}