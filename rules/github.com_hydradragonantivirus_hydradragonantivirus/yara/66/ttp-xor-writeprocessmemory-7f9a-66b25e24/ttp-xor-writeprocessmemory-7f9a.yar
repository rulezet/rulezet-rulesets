rule TTP_XOR_WriteProcessMemory_7f9a {
  strings:
    $key_7f9a = { 28 e8 [2] 1a ca [2] 1c ff [2] 32 ff [2] 0d e3 }

  condition:
    any of them
}