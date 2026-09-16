rule TTP_XOR_WriteProcessMemory_ea19 {
  strings:
    $key_ea19 = { bd 6b [2] 8f 49 [2] 89 7c [2] a7 7c [2] 98 60 }

  condition:
    any of them
}