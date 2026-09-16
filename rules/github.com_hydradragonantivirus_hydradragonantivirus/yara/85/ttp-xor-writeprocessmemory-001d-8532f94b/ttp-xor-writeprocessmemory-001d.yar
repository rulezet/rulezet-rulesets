rule TTP_XOR_WriteProcessMemory_001d {
  strings:
    $key_001d = { 57 6f [2] 65 4d [2] 63 78 [2] 4d 78 [2] 72 64 }

  condition:
    any of them
}