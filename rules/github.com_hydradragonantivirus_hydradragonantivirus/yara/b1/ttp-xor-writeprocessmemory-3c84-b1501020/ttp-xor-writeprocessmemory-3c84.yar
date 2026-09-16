rule TTP_XOR_WriteProcessMemory_3c84 {
  strings:
    $key_3c84 = { 6b f6 [2] 59 d4 [2] 5f e1 [2] 71 e1 [2] 4e fd }

  condition:
    any of them
}