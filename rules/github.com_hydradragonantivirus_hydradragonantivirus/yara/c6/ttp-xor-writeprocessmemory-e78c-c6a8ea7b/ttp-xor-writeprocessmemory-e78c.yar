rule TTP_XOR_WriteProcessMemory_e78c {
  strings:
    $key_e78c = { b0 fe [2] 82 dc [2] 84 e9 [2] aa e9 [2] 95 f5 }

  condition:
    any of them
}