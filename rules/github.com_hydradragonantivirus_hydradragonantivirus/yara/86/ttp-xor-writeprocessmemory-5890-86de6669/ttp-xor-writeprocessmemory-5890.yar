rule TTP_XOR_WriteProcessMemory_5890 {
  strings:
    $key_5890 = { 0f e2 [2] 3d c0 [2] 3b f5 [2] 15 f5 [2] 2a e9 }

  condition:
    any of them
}