rule TTP_XOR_WriteProcessMemory_18f9 {
  strings:
    $key_18f9 = { 4f 8b [2] 7d a9 [2] 7b 9c [2] 55 9c [2] 6a 80 }

  condition:
    any of them
}