rule TTP_XOR_WriteProcessMemory_459a {
  strings:
    $key_459a = { 12 e8 [2] 20 ca [2] 26 ff [2] 08 ff [2] 37 e3 }

  condition:
    any of them
}