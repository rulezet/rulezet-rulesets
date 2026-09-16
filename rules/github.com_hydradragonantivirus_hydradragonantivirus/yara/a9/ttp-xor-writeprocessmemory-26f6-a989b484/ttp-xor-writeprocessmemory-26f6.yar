rule TTP_XOR_WriteProcessMemory_26f6 {
  strings:
    $key_26f6 = { 71 84 [2] 43 a6 [2] 45 93 [2] 6b 93 [2] 54 8f }

  condition:
    any of them
}