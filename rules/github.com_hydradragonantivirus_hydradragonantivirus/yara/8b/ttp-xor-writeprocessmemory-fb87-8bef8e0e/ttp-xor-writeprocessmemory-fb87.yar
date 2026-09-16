rule TTP_XOR_WriteProcessMemory_fb87 {
  strings:
    $key_fb87 = { ac f5 [2] 9e d7 [2] 98 e2 [2] b6 e2 [2] 89 fe }

  condition:
    any of them
}