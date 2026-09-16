rule TTP_XOR_WriteProcessMemory_2da8 {
  strings:
    $key_2da8 = { 7a da [2] 48 f8 [2] 4e cd [2] 60 cd [2] 5f d1 }

  condition:
    any of them
}