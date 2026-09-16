rule TTP_XOR_WriteProcessMemory_5687 {
  strings:
    $key_5687 = { 01 f5 [2] 33 d7 [2] 35 e2 [2] 1b e2 [2] 24 fe }

  condition:
    any of them
}