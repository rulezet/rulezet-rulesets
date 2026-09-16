rule TTP_XOR_WriteProcessMemory_36d9 {
  strings:
    $key_36d9 = { 61 ab [2] 53 89 [2] 55 bc [2] 7b bc [2] 44 a0 }

  condition:
    any of them
}