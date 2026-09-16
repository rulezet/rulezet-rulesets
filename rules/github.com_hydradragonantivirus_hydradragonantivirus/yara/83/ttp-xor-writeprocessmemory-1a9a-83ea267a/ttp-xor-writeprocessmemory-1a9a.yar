rule TTP_XOR_WriteProcessMemory_1a9a {
  strings:
    $key_1a9a = { 4d e8 [2] 7f ca [2] 79 ff [2] 57 ff [2] 68 e3 }

  condition:
    any of them
}