rule TTP_XOR_WriteProcessMemory_3ea8 {
  strings:
    $key_3ea8 = { 69 da [2] 5b f8 [2] 5d cd [2] 73 cd [2] 4c d1 }

  condition:
    any of them
}