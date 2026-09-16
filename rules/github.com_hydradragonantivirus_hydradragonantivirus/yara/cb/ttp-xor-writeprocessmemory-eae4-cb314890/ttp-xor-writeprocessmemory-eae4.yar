rule TTP_XOR_WriteProcessMemory_eae4 {
  strings:
    $key_eae4 = { bd 96 [2] 8f b4 [2] 89 81 [2] a7 81 [2] 98 9d }

  condition:
    any of them
}