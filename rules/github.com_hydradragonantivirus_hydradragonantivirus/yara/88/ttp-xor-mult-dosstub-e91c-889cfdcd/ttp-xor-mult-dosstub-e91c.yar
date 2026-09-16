rule TTP_XOR_MULT_DOSStub_e91c {
  strings:
    $key_e91c = { bd 74 [2] c9 6c [2] 8e 6e [2] c9 7f [2] 87 73 [2] 8b 79 [2] 9c 72 [2] 87 3c [2] ba }

  condition:
    any of them
}