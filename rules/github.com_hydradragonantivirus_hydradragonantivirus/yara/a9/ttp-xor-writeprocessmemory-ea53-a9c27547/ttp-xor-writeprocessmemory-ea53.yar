rule TTP_XOR_WriteProcessMemory_ea53 {
  strings:
    $key_ea53 = { bd 21 [2] 8f 03 [2] 89 36 [2] a7 36 [2] 98 2a }

  condition:
    any of them
}