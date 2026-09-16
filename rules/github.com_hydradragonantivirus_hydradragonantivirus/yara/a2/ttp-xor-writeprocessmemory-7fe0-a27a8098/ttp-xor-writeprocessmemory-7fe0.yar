rule TTP_XOR_WriteProcessMemory_7fe0 {
  strings:
    $key_7fe0 = { 28 92 [2] 1a b0 [2] 1c 85 [2] 32 85 [2] 0d 99 }

  condition:
    any of them
}