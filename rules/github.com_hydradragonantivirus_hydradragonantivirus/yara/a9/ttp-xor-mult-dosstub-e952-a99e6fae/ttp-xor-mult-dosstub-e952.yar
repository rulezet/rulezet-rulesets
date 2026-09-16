rule TTP_XOR_MULT_DOSStub_e952 {
  strings:
    $key_e952 = { bd 3a [2] c9 22 [2] 8e 20 [2] c9 31 [2] 87 3d [2] 8b 37 [2] 9c 3c [2] 87 72 [2] ba }

  condition:
    any of them
}