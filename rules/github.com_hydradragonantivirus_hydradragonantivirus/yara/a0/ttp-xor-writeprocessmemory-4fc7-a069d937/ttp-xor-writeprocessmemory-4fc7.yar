rule TTP_XOR_WriteProcessMemory_4fc7 {
  strings:
    $key_4fc7 = { 18 b5 [2] 2a 97 [2] 2c a2 [2] 02 a2 [2] 3d be }

  condition:
    any of them
}