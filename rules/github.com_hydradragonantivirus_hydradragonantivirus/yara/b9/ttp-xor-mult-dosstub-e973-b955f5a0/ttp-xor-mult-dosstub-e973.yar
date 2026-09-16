rule TTP_XOR_MULT_DOSStub_e973 {
  strings:
    $key_e973 = { bd 1b [2] c9 03 [2] 8e 01 [2] c9 10 [2] 87 1c [2] 8b 16 [2] 9c 1d [2] 87 53 [2] ba }

  condition:
    any of them
}