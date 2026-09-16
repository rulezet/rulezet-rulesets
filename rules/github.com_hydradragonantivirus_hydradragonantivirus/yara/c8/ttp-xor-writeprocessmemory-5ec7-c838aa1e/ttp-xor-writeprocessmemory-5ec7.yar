rule TTP_XOR_WriteProcessMemory_5ec7 {
  strings:
    $key_5ec7 = { 09 b5 [2] 3b 97 [2] 3d a2 [2] 13 a2 [2] 2c be }

  condition:
    any of them
}