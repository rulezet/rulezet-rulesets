rule TTP_XOR_MULT_DOSStub_e92b {
  strings:
    $key_e92b = { bd 43 [2] c9 5b [2] 8e 59 [2] c9 48 [2] 87 44 [2] 8b 4e [2] 9c 45 [2] 87 0b [2] ba }

  condition:
    any of them
}