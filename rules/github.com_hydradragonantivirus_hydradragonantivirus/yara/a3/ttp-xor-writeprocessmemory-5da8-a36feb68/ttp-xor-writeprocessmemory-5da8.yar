rule TTP_XOR_WriteProcessMemory_5da8 {
  strings:
    $key_5da8 = { 0a da [2] 38 f8 [2] 3e cd [2] 10 cd [2] 2f d1 }

  condition:
    any of them
}