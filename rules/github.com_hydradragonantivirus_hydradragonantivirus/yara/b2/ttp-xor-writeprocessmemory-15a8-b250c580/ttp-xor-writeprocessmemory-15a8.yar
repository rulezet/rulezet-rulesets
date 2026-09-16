rule TTP_XOR_WriteProcessMemory_15a8 {
  strings:
    $key_15a8 = { 42 da [2] 70 f8 [2] 76 cd [2] 58 cd [2] 67 d1 }

  condition:
    any of them
}