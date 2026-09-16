rule TTP_XOR_WriteProcessMemory_6e92 {
  strings:
    $key_6e92 = { 39 e0 [2] 0b c2 [2] 0d f7 [2] 23 f7 [2] 1c eb }

  condition:
    any of them
}