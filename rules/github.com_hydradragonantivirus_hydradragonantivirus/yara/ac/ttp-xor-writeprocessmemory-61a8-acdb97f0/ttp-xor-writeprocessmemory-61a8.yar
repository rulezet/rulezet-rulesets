rule TTP_XOR_WriteProcessMemory_61a8 {
  strings:
    $key_61a8 = { 36 da [2] 04 f8 [2] 02 cd [2] 2c cd [2] 13 d1 }

  condition:
    any of them
}