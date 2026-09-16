rule TTP_XOR_WriteProcessMemory_dda8 {
  strings:
    $key_dda8 = { 8a da [2] b8 f8 [2] be cd [2] 90 cd [2] af d1 }

  condition:
    any of them
}