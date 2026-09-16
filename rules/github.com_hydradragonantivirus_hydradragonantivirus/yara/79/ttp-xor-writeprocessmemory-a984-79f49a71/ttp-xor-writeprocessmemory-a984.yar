rule TTP_XOR_WriteProcessMemory_a984 {
  strings:
    $key_a984 = { fe f6 [2] cc d4 [2] ca e1 [2] e4 e1 [2] db fd }

  condition:
    any of them
}