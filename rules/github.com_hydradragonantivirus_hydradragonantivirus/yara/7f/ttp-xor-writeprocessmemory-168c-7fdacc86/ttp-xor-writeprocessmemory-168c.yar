rule TTP_XOR_WriteProcessMemory_168c {
  strings:
    $key_168c = { 41 fe [2] 73 dc [2] 75 e9 [2] 5b e9 [2] 64 f5 }

  condition:
    any of them
}