rule TTP_XOR_WriteProcessMemory_ea9a {
  strings:
    $key_ea9a = { bd e8 [2] 8f ca [2] 89 ff [2] a7 ff [2] 98 e3 }

  condition:
    any of them
}