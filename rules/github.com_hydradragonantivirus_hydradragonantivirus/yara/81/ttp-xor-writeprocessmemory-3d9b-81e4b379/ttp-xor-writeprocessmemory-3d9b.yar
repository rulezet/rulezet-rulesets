rule TTP_XOR_WriteProcessMemory_3d9b {
  strings:
    $key_3d9b = { 6a e9 [2] 58 cb [2] 5e fe [2] 70 fe [2] 4f e2 }

  condition:
    any of them
}