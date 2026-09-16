rule TTP_XOR_WriteProcessMemory_34a8 {
  strings:
    $key_34a8 = { 63 da [2] 51 f8 [2] 57 cd [2] 79 cd [2] 46 d1 }

  condition:
    any of them
}