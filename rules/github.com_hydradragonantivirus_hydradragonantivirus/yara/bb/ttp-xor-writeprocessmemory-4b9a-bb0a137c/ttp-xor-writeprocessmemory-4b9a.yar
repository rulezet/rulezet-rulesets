rule TTP_XOR_WriteProcessMemory_4b9a {
  strings:
    $key_4b9a = { 1c e8 [2] 2e ca [2] 28 ff [2] 06 ff [2] 39 e3 }

  condition:
    any of them
}