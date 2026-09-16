rule TTP_XOR_WriteProcessMemory_5cd7 {
  strings:
    $key_5cd7 = { 0b a5 [2] 39 87 [2] 3f b2 [2] 11 b2 [2] 2e ae }

  condition:
    any of them
}