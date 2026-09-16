rule TTP_XOR_WriteProcessMemory_0cd3 {
  strings:
    $key_0cd3 = { 5b a1 [2] 69 83 [2] 6f b6 [2] 41 b6 [2] 7e aa }

  condition:
    any of them
}