rule TTP_XOR_WriteProcessMemory_1b9a {
  strings:
    $key_1b9a = { 4c e8 [2] 7e ca [2] 78 ff [2] 56 ff [2] 69 e3 }

  condition:
    any of them
}