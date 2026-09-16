rule TTP_XOR_MULT_DOSStub_e953 {
  strings:
    $key_e953 = { bd 3b [2] c9 23 [2] 8e 21 [2] c9 30 [2] 87 3c [2] 8b 36 [2] 9c 3d [2] 87 73 [2] ba }

  condition:
    any of them
}