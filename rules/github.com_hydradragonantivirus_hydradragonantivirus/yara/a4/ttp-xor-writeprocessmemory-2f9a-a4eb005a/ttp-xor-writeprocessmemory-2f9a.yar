rule TTP_XOR_WriteProcessMemory_2f9a {
  strings:
    $key_2f9a = { 78 e8 [2] 4a ca [2] 4c ff [2] 62 ff [2] 5d e3 }

  condition:
    any of them
}