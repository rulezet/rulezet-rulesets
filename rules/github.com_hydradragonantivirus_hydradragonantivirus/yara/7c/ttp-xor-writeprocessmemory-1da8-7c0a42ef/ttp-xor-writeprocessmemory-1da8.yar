rule TTP_XOR_WriteProcessMemory_1da8 {
  strings:
    $key_1da8 = { 4a da [2] 78 f8 [2] 7e cd [2] 50 cd [2] 6f d1 }

  condition:
    any of them
}