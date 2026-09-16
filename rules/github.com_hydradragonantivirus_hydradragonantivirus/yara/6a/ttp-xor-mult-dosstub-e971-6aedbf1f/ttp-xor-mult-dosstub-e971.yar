rule TTP_XOR_MULT_DOSStub_e971 {
  strings:
    $key_e971 = { bd 19 [2] c9 01 [2] 8e 03 [2] c9 12 [2] 87 1e [2] 8b 14 [2] 9c 1f [2] 87 51 [2] ba }

  condition:
    any of them
}