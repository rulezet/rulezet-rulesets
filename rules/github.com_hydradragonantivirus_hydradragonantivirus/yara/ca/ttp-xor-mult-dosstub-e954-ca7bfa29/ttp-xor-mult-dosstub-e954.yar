rule TTP_XOR_MULT_DOSStub_e954 {
  strings:
    $key_e954 = { bd 3c [2] c9 24 [2] 8e 26 [2] c9 37 [2] 87 3b [2] 8b 31 [2] 9c 3a [2] 87 74 [2] ba }

  condition:
    any of them
}