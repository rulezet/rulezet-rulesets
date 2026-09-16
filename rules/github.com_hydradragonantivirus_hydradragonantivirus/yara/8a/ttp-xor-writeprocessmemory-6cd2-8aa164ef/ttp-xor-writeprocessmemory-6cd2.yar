rule TTP_XOR_WriteProcessMemory_6cd2 {
  strings:
    $key_6cd2 = { 3b a0 [2] 09 82 [2] 0f b7 [2] 21 b7 [2] 1e ab }

  condition:
    any of them
}