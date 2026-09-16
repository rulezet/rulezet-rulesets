rule TTP_XOR_WriteProcessMemory_eae2 {
  strings:
    $key_eae2 = { bd 90 [2] 8f b2 [2] 89 87 [2] a7 87 [2] 98 9b }

  condition:
    any of them
}