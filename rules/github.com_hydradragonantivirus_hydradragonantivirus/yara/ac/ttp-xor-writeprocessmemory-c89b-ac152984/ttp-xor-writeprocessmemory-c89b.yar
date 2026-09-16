rule TTP_XOR_WriteProcessMemory_c89b {
  strings:
    $key_c89b = { 9f e9 [2] ad cb [2] ab fe [2] 85 fe [2] ba e2 }

  condition:
    any of them
}