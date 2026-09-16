rule TTP_XOR_WriteProcessMemory_eea8 {
  strings:
    $key_eea8 = { b9 da [2] 8b f8 [2] 8d cd [2] a3 cd [2] 9c d1 }

  condition:
    any of them
}