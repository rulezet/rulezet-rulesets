rule TTP_XOR_WriteProcessMemory_749a {
  strings:
    $key_749a = { 23 e8 [2] 11 ca [2] 17 ff [2] 39 ff [2] 06 e3 }

  condition:
    any of them
}