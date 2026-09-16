rule TTP_XOR_MULT_DOSStub_e9f2 {
  strings:
    $key_e9f2 = { bd 9a [2] c9 82 [2] 8e 80 [2] c9 91 [2] 87 9d [2] 8b 97 [2] 9c 9c [2] 87 d2 [2] ba }

  condition:
    any of them
}