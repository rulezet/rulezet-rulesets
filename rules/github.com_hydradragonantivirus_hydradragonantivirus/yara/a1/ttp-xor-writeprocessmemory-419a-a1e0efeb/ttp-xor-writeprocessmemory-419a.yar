rule TTP_XOR_WriteProcessMemory_419a {
  strings:
    $key_419a = { 16 e8 [2] 24 ca [2] 22 ff [2] 0c ff [2] 33 e3 }

  condition:
    any of them
}