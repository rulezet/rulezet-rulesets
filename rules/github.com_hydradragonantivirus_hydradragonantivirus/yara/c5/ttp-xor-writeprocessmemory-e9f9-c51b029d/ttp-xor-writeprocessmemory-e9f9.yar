rule TTP_XOR_WriteProcessMemory_e9f9 {
  strings:
    $key_e9f9 = { be 8b [2] 8c a9 [2] 8a 9c [2] a4 9c [2] 9b 80 }

  condition:
    any of them
}