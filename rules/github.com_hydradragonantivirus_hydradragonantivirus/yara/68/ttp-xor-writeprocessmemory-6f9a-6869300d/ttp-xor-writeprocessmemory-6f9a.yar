rule TTP_XOR_WriteProcessMemory_6f9a {
  strings:
    $key_6f9a = { 38 e8 [2] 0a ca [2] 0c ff [2] 22 ff [2] 1d e3 }

  condition:
    any of them
}