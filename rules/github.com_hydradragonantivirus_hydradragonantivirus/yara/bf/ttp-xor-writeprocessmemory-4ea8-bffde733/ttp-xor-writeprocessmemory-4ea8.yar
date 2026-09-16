rule TTP_XOR_WriteProcessMemory_4ea8 {
  strings:
    $key_4ea8 = { 19 da [2] 2b f8 [2] 2d cd [2] 03 cd [2] 3c d1 }

  condition:
    any of them
}