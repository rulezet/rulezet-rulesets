rule TTP_XOR_MULT_DOSStub_e906 {
  strings:
    $key_e906 = { bd 6e [2] c9 76 [2] 8e 74 [2] c9 65 [2] 87 69 [2] 8b 63 [2] 9c 68 [2] 87 26 [2] ba }

  condition:
    any of them
}