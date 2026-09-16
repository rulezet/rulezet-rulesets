rule TTP_XOR_MULT_DOSStub_e91a {
  strings:
    $key_e91a = { bd 72 [2] c9 6a [2] 8e 68 [2] c9 79 [2] 87 75 [2] 8b 7f [2] 9c 74 [2] 87 3a [2] ba }

  condition:
    any of them
}