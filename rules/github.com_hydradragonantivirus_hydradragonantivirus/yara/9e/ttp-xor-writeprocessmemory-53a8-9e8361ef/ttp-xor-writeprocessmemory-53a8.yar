rule TTP_XOR_WriteProcessMemory_53a8 {
  strings:
    $key_53a8 = { 04 da [2] 36 f8 [2] 30 cd [2] 1e cd [2] 21 d1 }

  condition:
    any of them
}