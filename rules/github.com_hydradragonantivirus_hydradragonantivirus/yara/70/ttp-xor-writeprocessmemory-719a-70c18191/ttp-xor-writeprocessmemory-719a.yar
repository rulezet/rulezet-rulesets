rule TTP_XOR_WriteProcessMemory_719a {
  strings:
    $key_719a = { 26 e8 [2] 14 ca [2] 12 ff [2] 3c ff [2] 03 e3 }

  condition:
    any of them
}