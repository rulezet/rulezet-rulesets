rule TTP_XOR_MULT_DOSStub_e93a {
  strings:
    $key_e93a = { bd 52 [2] c9 4a [2] 8e 48 [2] c9 59 [2] 87 55 [2] 8b 5f [2] 9c 54 [2] 87 1a [2] ba }

  condition:
    any of them
}