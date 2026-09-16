rule TTP_XOR_WriteProcessMemory_7da8 {
  strings:
    $key_7da8 = { 2a da [2] 18 f8 [2] 1e cd [2] 30 cd [2] 0f d1 }

  condition:
    any of them
}