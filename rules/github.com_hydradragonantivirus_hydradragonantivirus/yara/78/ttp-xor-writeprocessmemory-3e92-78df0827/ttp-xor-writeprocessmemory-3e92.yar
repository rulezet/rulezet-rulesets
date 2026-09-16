rule TTP_XOR_WriteProcessMemory_3e92 {
  strings:
    $key_3e92 = { 69 e0 [2] 5b c2 [2] 5d f7 [2] 73 f7 [2] 4c eb }

  condition:
    any of them
}