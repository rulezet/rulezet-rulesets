rule TTP_XOR_MULT_DOSStub_e95b {
  strings:
    $key_e95b = { bd 33 [2] c9 2b [2] 8e 29 [2] c9 38 [2] 87 34 [2] 8b 3e [2] 9c 35 [2] 87 7b [2] ba }

  condition:
    any of them
}