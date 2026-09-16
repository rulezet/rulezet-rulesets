rule TTP_XOR_MULT_DOSStub_e9ef {
  strings:
    $key_e9ef = { bd 87 [2] c9 9f [2] 8e 9d [2] c9 8c [2] 87 80 [2] 8b 8a [2] 9c 81 [2] 87 cf [2] ba }

  condition:
    any of them
}