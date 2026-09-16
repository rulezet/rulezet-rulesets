rule TTP_XOR_MULT_DOSStub_e9bf {
  strings:
    $key_e9bf = { bd d7 [2] c9 cf [2] 8e cd [2] c9 dc [2] 87 d0 [2] 8b da [2] 9c d1 [2] 87 9f [2] ba }

  condition:
    any of them
}