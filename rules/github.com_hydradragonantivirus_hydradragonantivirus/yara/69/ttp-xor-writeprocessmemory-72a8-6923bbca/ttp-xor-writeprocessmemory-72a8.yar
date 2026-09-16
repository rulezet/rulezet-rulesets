rule TTP_XOR_WriteProcessMemory_72a8 {
  strings:
    $key_72a8 = { 25 da [2] 17 f8 [2] 11 cd [2] 3f cd [2] 00 d1 }

  condition:
    any of them
}