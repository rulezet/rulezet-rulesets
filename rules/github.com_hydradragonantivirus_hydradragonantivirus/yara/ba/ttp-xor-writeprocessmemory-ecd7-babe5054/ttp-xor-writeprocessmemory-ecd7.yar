rule TTP_XOR_WriteProcessMemory_ecd7 {
  strings:
    $key_ecd7 = { bb a5 [2] 89 87 [2] 8f b2 [2] a1 b2 [2] 9e ae }

  condition:
    any of them
}