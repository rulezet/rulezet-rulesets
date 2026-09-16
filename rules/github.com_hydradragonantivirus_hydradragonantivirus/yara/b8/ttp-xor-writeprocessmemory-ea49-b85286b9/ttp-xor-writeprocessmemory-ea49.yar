rule TTP_XOR_WriteProcessMemory_ea49 {
  strings:
    $key_ea49 = { bd 3b [2] 8f 19 [2] 89 2c [2] a7 2c [2] 98 30 }

  condition:
    any of them
}