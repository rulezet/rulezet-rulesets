rule TTP_XOR_WriteProcessMemory_08e9 {
  strings:
    $key_08e9 = { 5f 9b [2] 6d b9 [2] 6b 8c [2] 45 8c [2] 7a 90 }

  condition:
    any of them
}