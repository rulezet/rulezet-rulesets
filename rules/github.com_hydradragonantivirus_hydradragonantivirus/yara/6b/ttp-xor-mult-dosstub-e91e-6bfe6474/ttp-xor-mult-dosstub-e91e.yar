rule TTP_XOR_MULT_DOSStub_e91e {
  strings:
    $key_e91e = { bd 76 [2] c9 6e [2] 8e 6c [2] c9 7d [2] 87 71 [2] 8b 7b [2] 9c 70 [2] 87 3e [2] ba }

  condition:
    any of them
}