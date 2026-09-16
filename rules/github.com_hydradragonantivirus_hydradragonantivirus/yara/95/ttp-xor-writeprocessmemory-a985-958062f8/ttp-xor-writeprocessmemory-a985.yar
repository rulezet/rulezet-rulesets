rule TTP_XOR_WriteProcessMemory_a985 {
  strings:
    $key_a985 = { fe f7 [2] cc d5 [2] ca e0 [2] e4 e0 [2] db fc }

  condition:
    any of them
}