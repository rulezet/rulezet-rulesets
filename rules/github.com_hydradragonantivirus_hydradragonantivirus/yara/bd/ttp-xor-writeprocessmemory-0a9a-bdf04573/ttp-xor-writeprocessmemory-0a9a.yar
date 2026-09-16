rule TTP_XOR_WriteProcessMemory_0a9a {
  strings:
    $key_0a9a = { 5d e8 [2] 6f ca [2] 69 ff [2] 47 ff [2] 78 e3 }

  condition:
    any of them
}