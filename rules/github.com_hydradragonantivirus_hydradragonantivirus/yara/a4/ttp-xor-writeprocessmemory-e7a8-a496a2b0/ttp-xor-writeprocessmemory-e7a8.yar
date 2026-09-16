rule TTP_XOR_WriteProcessMemory_e7a8 {
  strings:
    $key_e7a8 = { b0 da [2] 82 f8 [2] 84 cd [2] aa cd [2] 95 d1 }

  condition:
    any of them
}