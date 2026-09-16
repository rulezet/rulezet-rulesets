rule TTP_XOR_WriteProcessMemory_ea34 {
  strings:
    $key_ea34 = { bd 46 [2] 8f 64 [2] 89 51 [2] a7 51 [2] 98 4d }

  condition:
    any of them
}