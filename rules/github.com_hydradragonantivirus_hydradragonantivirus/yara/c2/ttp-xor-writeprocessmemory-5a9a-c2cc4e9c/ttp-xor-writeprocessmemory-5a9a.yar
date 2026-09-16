rule TTP_XOR_WriteProcessMemory_5a9a {
  strings:
    $key_5a9a = { 0d e8 [2] 3f ca [2] 39 ff [2] 17 ff [2] 28 e3 }

  condition:
    any of them
}