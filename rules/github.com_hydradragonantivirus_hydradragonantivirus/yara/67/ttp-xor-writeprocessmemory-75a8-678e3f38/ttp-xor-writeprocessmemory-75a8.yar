rule TTP_XOR_WriteProcessMemory_75a8 {
  strings:
    $key_75a8 = { 22 da [2] 10 f8 [2] 16 cd [2] 38 cd [2] 07 d1 }

  condition:
    any of them
}