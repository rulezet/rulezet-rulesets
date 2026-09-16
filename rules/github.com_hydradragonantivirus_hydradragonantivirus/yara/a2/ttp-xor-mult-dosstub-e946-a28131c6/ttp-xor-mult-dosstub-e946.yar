rule TTP_XOR_MULT_DOSStub_e946 {
  strings:
    $key_e946 = { bd 2e [2] c9 36 [2] 8e 34 [2] c9 25 [2] 87 29 [2] 8b 23 [2] 9c 28 [2] 87 66 [2] ba }

  condition:
    any of them
}