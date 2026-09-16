rule TTP_XOR_WriteProcessMemory_7086 {
  strings:
    $key_7086 = { 27 f4 [2] 15 d6 [2] 13 e3 [2] 3d e3 [2] 02 ff }

  condition:
    any of them
}