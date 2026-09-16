rule TTP_XOR_MULT_DOSStub_e930 {
  strings:
    $key_e930 = { bd 58 [2] c9 40 [2] 8e 42 [2] c9 53 [2] 87 5f [2] 8b 55 [2] 9c 5e [2] 87 10 [2] ba }

  condition:
    any of them
}