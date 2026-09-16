rule TTP_XOR_MULT_DOSStub_e964 {
  strings:
    $key_e964 = { bd 0c [2] c9 14 [2] 8e 16 [2] c9 07 [2] 87 0b [2] 8b 01 [2] 9c 0a [2] 87 44 [2] ba }

  condition:
    any of them
}