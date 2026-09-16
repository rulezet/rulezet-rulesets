rule TTP_XOR_WriteProcessMemory_32a8 {
  strings:
    $key_32a8 = { 65 da [2] 57 f8 [2] 51 cd [2] 7f cd [2] 40 d1 }

  condition:
    any of them
}