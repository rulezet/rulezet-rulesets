rule TTP_XOR_WriteProcessMemory_58d9 {
  strings:
    $key_58d9 = { 0f ab [2] 3d 89 [2] 3b bc [2] 15 bc [2] 2a a0 }

  condition:
    any of them
}