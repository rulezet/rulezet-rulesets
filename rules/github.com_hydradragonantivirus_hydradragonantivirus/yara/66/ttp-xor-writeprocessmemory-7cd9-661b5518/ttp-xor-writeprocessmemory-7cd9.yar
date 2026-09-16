rule TTP_XOR_WriteProcessMemory_7cd9 {
  strings:
    $key_7cd9 = { 2b ab [2] 19 89 [2] 1f bc [2] 31 bc [2] 0e a0 }

  condition:
    any of them
}