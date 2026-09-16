rule TTP_XOR_WriteProcessMemory_ea05 {
  strings:
    $key_ea05 = { bd 77 [2] 8f 55 [2] 89 60 [2] a7 60 [2] 98 7c }

  condition:
    any of them
}