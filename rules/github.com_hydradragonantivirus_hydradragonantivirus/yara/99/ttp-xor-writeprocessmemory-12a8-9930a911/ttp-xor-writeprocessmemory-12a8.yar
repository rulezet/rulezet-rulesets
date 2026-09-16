rule TTP_XOR_WriteProcessMemory_12a8 {
  strings:
    $key_12a8 = { 45 da [2] 77 f8 [2] 71 cd [2] 5f cd [2] 60 d1 }

  condition:
    any of them
}