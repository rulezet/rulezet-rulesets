rule TTP_XOR_WriteProcessMemory_6cd3 {
  strings:
    $key_6cd3 = { 3b a1 [2] 09 83 [2] 0f b6 [2] 21 b6 [2] 1e aa }

  condition:
    any of them
}