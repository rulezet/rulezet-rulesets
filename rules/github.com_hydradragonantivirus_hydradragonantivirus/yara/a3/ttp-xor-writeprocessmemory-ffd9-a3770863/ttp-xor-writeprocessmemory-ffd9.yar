rule TTP_XOR_WriteProcessMemory_ffd9 {
  strings:
    $key_ffd9 = { a8 ab [2] 9a 89 [2] 9c bc [2] b2 bc [2] 8d a0 }

  condition:
    any of them
}