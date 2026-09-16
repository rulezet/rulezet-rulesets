rule TTP_XOR_WriteProcessMemory_638d {
  strings:
    $key_638d = { 34 ff [2] 06 dd [2] 00 e8 [2] 2e e8 [2] 11 f4 }

  condition:
    any of them
}