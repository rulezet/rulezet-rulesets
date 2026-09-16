rule TTP_XOR_MULT_DOSStub_e9f3 {
  strings:
    $key_e9f3 = { bd 9b [2] c9 83 [2] 8e 81 [2] c9 90 [2] 87 9c [2] 8b 96 [2] 9c 9d [2] 87 d3 [2] ba }

  condition:
    any of them
}