rule TTP_XOR_WriteProcessMemory_46a8 {
  strings:
    $key_46a8 = { 11 da [2] 23 f8 [2] 25 cd [2] 0b cd [2] 34 d1 }

  condition:
    any of them
}