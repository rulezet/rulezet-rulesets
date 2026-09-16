rule TTP_XOR_WriteProcessMemory_ea15 {
  strings:
    $key_ea15 = { bd 67 [2] 8f 45 [2] 89 70 [2] a7 70 [2] 98 6c }

  condition:
    any of them
}