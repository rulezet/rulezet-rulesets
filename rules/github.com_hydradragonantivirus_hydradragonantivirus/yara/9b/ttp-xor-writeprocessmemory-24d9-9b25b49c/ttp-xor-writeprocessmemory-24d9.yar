rule TTP_XOR_WriteProcessMemory_24d9 {
  strings:
    $key_24d9 = { 73 ab [2] 41 89 [2] 47 bc [2] 69 bc [2] 56 a0 }

  condition:
    any of them
}