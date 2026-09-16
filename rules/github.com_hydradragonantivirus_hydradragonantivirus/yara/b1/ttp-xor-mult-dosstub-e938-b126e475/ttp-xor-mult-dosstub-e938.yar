rule TTP_XOR_MULT_DOSStub_e938 {
  strings:
    $key_e938 = { bd 50 [2] c9 48 [2] 8e 4a [2] c9 5b [2] 87 57 [2] 8b 5d [2] 9c 56 [2] 87 18 [2] ba }

  condition:
    any of them
}