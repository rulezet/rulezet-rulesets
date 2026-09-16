rule TTP_XOR_WriteProcessMemory_74a8 {
  strings:
    $key_74a8 = { 23 da [2] 11 f8 [2] 17 cd [2] 39 cd [2] 06 d1 }

  condition:
    any of them
}