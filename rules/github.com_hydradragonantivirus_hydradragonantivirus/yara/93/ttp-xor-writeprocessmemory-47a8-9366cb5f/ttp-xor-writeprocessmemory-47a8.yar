rule TTP_XOR_WriteProcessMemory_47a8 {
  strings:
    $key_47a8 = { 10 da [2] 22 f8 [2] 24 cd [2] 0a cd [2] 35 d1 }

  condition:
    any of them
}