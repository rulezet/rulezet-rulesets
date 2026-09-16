rule TTP_XOR_WriteProcessMemory_5e35 {
  strings:
    $key_5e35 = { 09 47 [2] 3b 65 [2] 3d 50 [2] 13 50 [2] 2c 4c }

  condition:
    any of them
}