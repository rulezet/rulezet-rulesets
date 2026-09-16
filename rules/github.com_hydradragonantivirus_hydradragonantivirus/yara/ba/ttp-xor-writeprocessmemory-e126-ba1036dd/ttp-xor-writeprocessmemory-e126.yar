rule TTP_XOR_WriteProcessMemory_e126 {
  strings:
    $key_e126 = { b6 54 [2] 84 76 [2] 82 43 [2] ac 43 [2] 93 5f }

  condition:
    any of them
}