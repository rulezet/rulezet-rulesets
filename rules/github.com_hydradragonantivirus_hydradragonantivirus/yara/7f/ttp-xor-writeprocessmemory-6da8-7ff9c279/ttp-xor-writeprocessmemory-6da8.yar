rule TTP_XOR_WriteProcessMemory_6da8 {
  strings:
    $key_6da8 = { 3a da [2] 08 f8 [2] 0e cd [2] 20 cd [2] 1f d1 }

  condition:
    any of them
}