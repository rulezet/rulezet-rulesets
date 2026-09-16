rule TTP_XOR_WriteProcessMemory_7687 {
  strings:
    $key_7687 = { 21 f5 [2] 13 d7 [2] 15 e2 [2] 3b e2 [2] 04 fe }

  condition:
    any of them
}