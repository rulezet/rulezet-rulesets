rule TTP_XOR_WriteProcessMemory_fb86 {
  strings:
    $key_fb86 = { ac f4 [2] 9e d6 [2] 98 e3 [2] b6 e3 [2] 89 ff }

  condition:
    any of them
}