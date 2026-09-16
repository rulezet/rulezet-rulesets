rule TTP_XOR_WriteProcessMemory_e4a8 {
  strings:
    $key_e4a8 = { b3 da [2] 81 f8 [2] 87 cd [2] a9 cd [2] 96 d1 }

  condition:
    any of them
}