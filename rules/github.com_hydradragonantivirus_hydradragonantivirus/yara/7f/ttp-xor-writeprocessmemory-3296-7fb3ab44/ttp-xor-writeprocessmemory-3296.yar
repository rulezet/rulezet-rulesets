rule TTP_XOR_WriteProcessMemory_3296 {
  strings:
    $key_3296 = { 65 e4 [2] 57 c6 [2] 51 f3 [2] 7f f3 [2] 40 ef }

  condition:
    any of them
}