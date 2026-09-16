rule TTP_XOR_MULT_DOSStub_e90b {
  strings:
    $key_e90b = { bd 63 [2] c9 7b [2] 8e 79 [2] c9 68 [2] 87 64 [2] 8b 6e [2] 9c 65 [2] 87 2b [2] ba }

  condition:
    any of them
}