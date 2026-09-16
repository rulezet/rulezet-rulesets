rule TTP_XOR_WriteProcessMemory_0b9a {
  strings:
    $key_0b9a = { 5c e8 [2] 6e ca [2] 68 ff [2] 46 ff [2] 79 e3 }

  condition:
    any of them
}