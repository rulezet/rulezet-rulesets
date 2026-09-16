rule TTP_XOR_WriteProcessMemory_3bf9 {
  strings:
    $key_3bf9 = { 6c 8b [2] 5e a9 [2] 58 9c [2] 76 9c [2] 49 80 }

  condition:
    any of them
}