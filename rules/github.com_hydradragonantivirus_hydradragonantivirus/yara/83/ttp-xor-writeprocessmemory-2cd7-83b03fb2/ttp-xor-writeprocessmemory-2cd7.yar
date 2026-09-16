rule TTP_XOR_WriteProcessMemory_2cd7 {
  strings:
    $key_2cd7 = { 7b a5 [2] 49 87 [2] 4f b2 [2] 61 b2 [2] 5e ae }

  condition:
    any of them
}