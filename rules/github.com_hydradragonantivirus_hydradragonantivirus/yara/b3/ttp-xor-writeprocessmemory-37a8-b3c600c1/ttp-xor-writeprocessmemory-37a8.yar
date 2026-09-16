rule TTP_XOR_WriteProcessMemory_37a8 {
  strings:
    $key_37a8 = { 60 da [2] 52 f8 [2] 54 cd [2] 7a cd [2] 45 d1 }

  condition:
    any of them
}