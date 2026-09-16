rule TTP_XOR_WriteProcessMemory_ea09 {
  strings:
    $key_ea09 = { bd 7b [2] 8f 59 [2] 89 6c [2] a7 6c [2] 98 70 }

  condition:
    any of them
}