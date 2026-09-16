rule TTP_XOR_WriteProcessMemory_ffc7 {
  strings:
    $key_ffc7 = { a8 b5 [2] 9a 97 [2] 9c a2 [2] b2 a2 [2] 8d be }

  condition:
    any of them
}