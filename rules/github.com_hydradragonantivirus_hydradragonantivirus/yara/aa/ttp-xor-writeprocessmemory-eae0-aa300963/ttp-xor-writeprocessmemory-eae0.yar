rule TTP_XOR_WriteProcessMemory_eae0 {
  strings:
    $key_eae0 = { bd 92 [2] 8f b0 [2] 89 85 [2] a7 85 [2] 98 99 }

  condition:
    any of them
}