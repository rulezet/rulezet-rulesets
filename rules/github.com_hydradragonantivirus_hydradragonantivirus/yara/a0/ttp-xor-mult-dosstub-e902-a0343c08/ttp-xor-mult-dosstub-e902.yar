rule TTP_XOR_MULT_DOSStub_e902 {
  strings:
    $key_e902 = { bd 6a [2] c9 72 [2] 8e 70 [2] c9 61 [2] 87 6d [2] 8b 67 [2] 9c 6c [2] 87 22 [2] ba }

  condition:
    any of them
}