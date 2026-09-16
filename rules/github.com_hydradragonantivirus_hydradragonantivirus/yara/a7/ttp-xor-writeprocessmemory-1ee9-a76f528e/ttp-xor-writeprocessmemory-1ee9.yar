rule TTP_XOR_WriteProcessMemory_1ee9 {
  strings:
    $key_1ee9 = { 49 9b [2] 7b b9 [2] 7d 8c [2] 53 8c [2] 6c 90 }

  condition:
    any of them
}