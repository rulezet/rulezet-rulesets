rule TTP_XOR_WriteProcessMemory_fb02 {
  strings:
    $key_fb02 = { ac 70 [2] 9e 52 [2] 98 67 [2] b6 67 [2] 89 7b }

  condition:
    any of them
}