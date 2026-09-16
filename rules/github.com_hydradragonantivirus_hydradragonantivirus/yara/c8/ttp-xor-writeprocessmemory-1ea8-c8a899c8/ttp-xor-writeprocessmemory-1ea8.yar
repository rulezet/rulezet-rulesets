rule TTP_XOR_WriteProcessMemory_1ea8 {
  strings:
    $key_1ea8 = { 49 da [2] 7b f8 [2] 7d cd [2] 53 cd [2] 6c d1 }

  condition:
    any of them
}