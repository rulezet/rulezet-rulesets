rule TTP_XOR_WriteProcessMemory_ea03 {
  strings:
    $key_ea03 = { bd 71 [2] 8f 53 [2] 89 66 [2] a7 66 [2] 98 7a }

  condition:
    any of them
}