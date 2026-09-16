rule TTP_XOR_WriteProcessMemory_fb9b {
  strings:
    $key_fb9b = { ac e9 [2] 9e cb [2] 98 fe [2] b6 fe [2] 89 e2 }

  condition:
    any of them
}