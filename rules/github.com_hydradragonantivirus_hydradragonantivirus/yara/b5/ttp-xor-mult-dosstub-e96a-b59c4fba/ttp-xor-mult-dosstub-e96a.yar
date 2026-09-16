rule TTP_XOR_MULT_DOSStub_e96a {
  strings:
    $key_e96a = { bd 02 [2] c9 1a [2] 8e 18 [2] c9 09 [2] 87 05 [2] 8b 0f [2] 9c 04 [2] 87 4a [2] ba }

  condition:
    any of them
}