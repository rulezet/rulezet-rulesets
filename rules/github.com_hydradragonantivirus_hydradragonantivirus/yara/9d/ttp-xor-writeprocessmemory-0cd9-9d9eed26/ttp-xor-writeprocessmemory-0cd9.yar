rule TTP_XOR_WriteProcessMemory_0cd9 {
  strings:
    $key_0cd9 = { 5b ab [2] 69 89 [2] 6f bc [2] 41 bc [2] 7e a0 }

  condition:
    any of them
}