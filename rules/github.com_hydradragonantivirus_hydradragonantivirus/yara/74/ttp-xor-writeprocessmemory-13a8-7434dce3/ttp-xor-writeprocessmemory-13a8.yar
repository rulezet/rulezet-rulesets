rule TTP_XOR_WriteProcessMemory_13a8 {
  strings:
    $key_13a8 = { 44 da [2] 76 f8 [2] 70 cd [2] 5e cd [2] 61 d1 }

  condition:
    any of them
}