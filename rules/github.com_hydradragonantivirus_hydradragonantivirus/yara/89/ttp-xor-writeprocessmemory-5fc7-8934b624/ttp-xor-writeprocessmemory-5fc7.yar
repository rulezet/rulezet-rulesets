rule TTP_XOR_WriteProcessMemory_5fc7 {
  strings:
    $key_5fc7 = { 08 b5 [2] 3a 97 [2] 3c a2 [2] 12 a2 [2] 2d be }

  condition:
    any of them
}