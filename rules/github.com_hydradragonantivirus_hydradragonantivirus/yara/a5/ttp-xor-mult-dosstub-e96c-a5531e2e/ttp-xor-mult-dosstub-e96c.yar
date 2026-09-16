rule TTP_XOR_MULT_DOSStub_e96c {
  strings:
    $key_e96c = { bd 04 [2] c9 1c [2] 8e 1e [2] c9 0f [2] 87 03 [2] 8b 09 [2] 9c 02 [2] 87 4c [2] ba }

  condition:
    any of them
}