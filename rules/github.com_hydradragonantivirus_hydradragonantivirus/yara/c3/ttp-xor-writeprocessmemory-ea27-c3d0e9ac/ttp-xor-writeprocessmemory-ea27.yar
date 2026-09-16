rule TTP_XOR_WriteProcessMemory_ea27 {
  strings:
    $key_ea27 = { bd 55 [2] 8f 77 [2] 89 42 [2] a7 42 [2] 98 5e }

  condition:
    any of them
}