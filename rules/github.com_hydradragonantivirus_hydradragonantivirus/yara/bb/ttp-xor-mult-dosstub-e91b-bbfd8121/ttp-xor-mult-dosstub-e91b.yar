rule TTP_XOR_MULT_DOSStub_e91b {
  strings:
    $key_e91b = { bd 73 [2] c9 6b [2] 8e 69 [2] c9 78 [2] 87 74 [2] 8b 7e [2] 9c 75 [2] 87 3b [2] ba }

  condition:
    any of them
}