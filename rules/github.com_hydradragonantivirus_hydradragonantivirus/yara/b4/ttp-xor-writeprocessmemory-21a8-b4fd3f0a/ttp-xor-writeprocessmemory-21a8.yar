rule TTP_XOR_WriteProcessMemory_21a8 {
  strings:
    $key_21a8 = { 76 da [2] 44 f8 [2] 42 cd [2] 6c cd [2] 53 d1 }

  condition:
    any of them
}