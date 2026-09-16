rule TTP_XOR_WriteProcessMemory_e8d9 {
  strings:
    $key_e8d9 = { bf ab [2] 8d 89 [2] 8b bc [2] a5 bc [2] 9a a0 }

  condition:
    any of them
}