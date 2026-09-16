rule TTP_XOR_WriteProcessMemory_09b4 {
  strings:
    $key_09b4 = { 5e c6 [2] 6c e4 [2] 6a d1 [2] 44 d1 [2] 7b cd }

  condition:
    any of them
}