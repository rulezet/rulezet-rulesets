rule TTP_XOR_MULT_DOSStub_e962 {
  strings:
    $key_e962 = { bd 0a [2] c9 12 [2] 8e 10 [2] c9 01 [2] 87 0d [2] 8b 07 [2] 9c 0c [2] 87 42 [2] ba }

  condition:
    any of them
}