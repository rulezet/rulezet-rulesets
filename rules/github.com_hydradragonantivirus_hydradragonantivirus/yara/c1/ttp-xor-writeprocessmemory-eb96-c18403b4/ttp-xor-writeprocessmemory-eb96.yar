rule TTP_XOR_WriteProcessMemory_eb96 {
  strings:
    $key_eb96 = { bc e4 [2] 8e c6 [2] 88 f3 [2] a6 f3 [2] 99 ef }

  condition:
    any of them
}