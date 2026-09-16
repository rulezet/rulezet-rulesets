rule TTP_XOR_WriteProcessMemory_eb90 {
  strings:
    $key_eb90 = { bc e2 [2] 8e c0 [2] 88 f5 [2] a6 f5 [2] 99 e9 }

  condition:
    any of them
}