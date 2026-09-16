rule TTP_XOR_WriteProcessMemory_efe0 {
  strings:
    $key_efe0 = { b8 92 [2] 8a b0 [2] 8c 85 [2] a2 85 [2] 9d 99 }

  condition:
    any of them
}