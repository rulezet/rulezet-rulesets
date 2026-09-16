rule TTP_XOR_WriteProcessMemory_ea66 {
  strings:
    $key_ea66 = { bd 14 [2] 8f 36 [2] 89 03 [2] a7 03 [2] 98 1f }

  condition:
    any of them
}