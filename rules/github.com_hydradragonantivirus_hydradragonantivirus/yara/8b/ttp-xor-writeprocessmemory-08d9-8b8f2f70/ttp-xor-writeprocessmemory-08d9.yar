rule TTP_XOR_WriteProcessMemory_08d9 {
  strings:
    $key_08d9 = { 5f ab [2] 6d 89 [2] 6b bc [2] 45 bc [2] 7a a0 }

  condition:
    any of them
}