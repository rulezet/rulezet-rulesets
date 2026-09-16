rule TTP_XOR_WriteProcessMemory_2ae9 {
  strings:
    $key_2ae9 = { 7d 9b [2] 4f b9 [2] 49 8c [2] 67 8c [2] 58 90 }

  condition:
    any of them
}