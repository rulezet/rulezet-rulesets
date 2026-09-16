rule TTP_XOR_WriteProcessMemory_db9b {
  strings:
    $key_db9b = { 8c e9 [2] be cb [2] b8 fe [2] 96 fe [2] a9 e2 }

  condition:
    any of them
}