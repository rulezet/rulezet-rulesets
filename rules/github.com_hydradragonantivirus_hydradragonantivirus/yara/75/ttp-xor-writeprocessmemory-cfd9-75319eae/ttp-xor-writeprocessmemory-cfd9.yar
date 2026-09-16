rule TTP_XOR_WriteProcessMemory_cfd9 {
  strings:
    $key_cfd9 = { 98 ab [2] aa 89 [2] ac bc [2] 82 bc [2] bd a0 }

  condition:
    any of them
}