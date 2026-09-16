rule TTP_XOR_MULT_DOSStub_e9ec {
  strings:
    $key_e9ec = { bd 84 [2] c9 9c [2] 8e 9e [2] c9 8f [2] 87 83 [2] 8b 89 [2] 9c 82 [2] 87 cc [2] ba }

  condition:
    any of them
}