rule TTP_XOR_WriteProcessMemory_ea64 {
  strings:
    $key_ea64 = { bd 16 [2] 8f 34 [2] 89 01 [2] a7 01 [2] 98 1d }

  condition:
    any of them
}