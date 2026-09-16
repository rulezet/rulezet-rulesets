rule TTP_XOR_WriteProcessMemory_78d9 {
  strings:
    $key_78d9 = { 2f ab [2] 1d 89 [2] 1b bc [2] 35 bc [2] 0a a0 }

  condition:
    any of them
}