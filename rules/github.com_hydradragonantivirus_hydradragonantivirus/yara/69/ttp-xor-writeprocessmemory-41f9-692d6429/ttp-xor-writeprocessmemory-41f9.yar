rule TTP_XOR_WriteProcessMemory_41f9 {
  strings:
    $key_41f9 = { 16 8b [2] 24 a9 [2] 22 9c [2] 0c 9c [2] 33 80 }

  condition:
    any of them
}