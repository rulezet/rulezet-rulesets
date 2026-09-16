rule TTP_XOR_MULT_DOSStub_f9bf {
  strings:
    $key_f9bf = { ad d7 [2] d9 cf [2] 9e cd [2] d9 dc [2] 97 d0 [2] 9b da [2] 8c d1 [2] 97 9f [2] aa }

  condition:
    any of them
}