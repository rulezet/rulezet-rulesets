rule TTP_XOR_WriteProcessMemory_7c84 {
  strings:
    $key_7c84 = { 2b f6 [2] 19 d4 [2] 1f e1 [2] 31 e1 [2] 0e fd }

  condition:
    any of them
}