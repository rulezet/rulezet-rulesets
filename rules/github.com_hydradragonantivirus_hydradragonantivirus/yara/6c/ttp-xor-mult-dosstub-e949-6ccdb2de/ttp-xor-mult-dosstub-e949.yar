rule TTP_XOR_MULT_DOSStub_e949 {
  strings:
    $key_e949 = { bd 21 [2] c9 39 [2] 8e 3b [2] c9 2a [2] 87 26 [2] 8b 2c [2] 9c 27 [2] 87 69 [2] ba }

  condition:
    any of them
}