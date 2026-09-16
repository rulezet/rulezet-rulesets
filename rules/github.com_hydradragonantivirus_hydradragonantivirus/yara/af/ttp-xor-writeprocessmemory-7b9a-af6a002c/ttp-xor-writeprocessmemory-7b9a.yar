rule TTP_XOR_WriteProcessMemory_7b9a {
  strings:
    $key_7b9a = { 2c e8 [2] 1e ca [2] 18 ff [2] 36 ff [2] 09 e3 }

  condition:
    any of them
}