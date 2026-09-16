rule TTP_XOR_WriteProcessMemory_349a {
  strings:
    $key_349a = { 63 e8 [2] 51 ca [2] 57 ff [2] 79 ff [2] 46 e3 }

  condition:
    any of them
}