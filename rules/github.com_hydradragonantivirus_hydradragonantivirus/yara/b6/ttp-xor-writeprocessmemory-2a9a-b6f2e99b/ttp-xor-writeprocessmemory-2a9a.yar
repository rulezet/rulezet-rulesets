rule TTP_XOR_WriteProcessMemory_2a9a {
  strings:
    $key_2a9a = { 7d e8 [2] 4f ca [2] 49 ff [2] 67 ff [2] 58 e3 }

  condition:
    any of them
}