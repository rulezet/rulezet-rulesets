rule TTP_XOR_WriteProcessMemory_11a8 {
  strings:
    $key_11a8 = { 46 da [2] 74 f8 [2] 72 cd [2] 5c cd [2] 63 d1 }

  condition:
    any of them
}