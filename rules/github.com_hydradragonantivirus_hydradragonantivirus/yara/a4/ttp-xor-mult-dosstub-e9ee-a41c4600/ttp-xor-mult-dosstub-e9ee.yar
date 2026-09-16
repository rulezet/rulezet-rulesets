rule TTP_XOR_MULT_DOSStub_e9ee {
  strings:
    $key_e9ee = { bd 86 [2] c9 9e [2] 8e 9c [2] c9 8d [2] 87 81 [2] 8b 8b [2] 9c 80 [2] 87 ce [2] ba }

  condition:
    any of them
}