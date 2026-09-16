rule TTP_XOR_WriteProcessMemory_08c4 {
  strings:
    $key_08c4 = { 5f b6 [2] 6d 94 [2] 6b a1 [2] 45 a1 [2] 7a bd }

  condition:
    any of them
}