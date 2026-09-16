rule TTP_XOR_WriteProcessMemory_12e9 {
  strings:
    $key_12e9 = { 45 9b [2] 77 b9 [2] 71 8c [2] 5f 8c [2] 60 90 }

  condition:
    any of them
}