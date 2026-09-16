rule TTP_XOR_WriteProcessMemory_2687 {
  strings:
    $key_2687 = { 71 f5 [2] 43 d7 [2] 45 e2 [2] 6b e2 [2] 54 fe }

  condition:
    any of them
}