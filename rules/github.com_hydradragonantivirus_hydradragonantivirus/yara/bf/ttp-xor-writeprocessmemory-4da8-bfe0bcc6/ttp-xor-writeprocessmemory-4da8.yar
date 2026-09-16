rule TTP_XOR_WriteProcessMemory_4da8 {
  strings:
    $key_4da8 = { 1a da [2] 28 f8 [2] 2e cd [2] 00 cd [2] 3f d1 }

  condition:
    any of them
}