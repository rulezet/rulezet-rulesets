rule TTP_XOR_WriteProcessMemory_1687 {
  strings:
    $key_1687 = { 41 f5 [2] 73 d7 [2] 75 e2 [2] 5b e2 [2] 64 fe }

  condition:
    any of them
}