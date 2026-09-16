rule TTP_XOR_WriteProcessMemory_ea44 {
  strings:
    $key_ea44 = { bd 36 [2] 8f 14 [2] 89 21 [2] a7 21 [2] 98 3d }

  condition:
    any of them
}