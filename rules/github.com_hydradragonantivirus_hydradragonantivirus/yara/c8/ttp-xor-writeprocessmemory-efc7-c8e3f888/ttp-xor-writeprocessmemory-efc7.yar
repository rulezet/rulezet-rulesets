rule TTP_XOR_WriteProcessMemory_efc7 {
  strings:
    $key_efc7 = { b8 b5 [2] 8a 97 [2] 8c a2 [2] a2 a2 [2] 9d be }

  condition:
    any of them
}