rule TTP_XOR_WriteProcessMemory_008d {
  strings:
    $key_008d = { 57 ff [2] 65 dd [2] 63 e8 [2] 4d e8 [2] 72 f4 }

  condition:
    any of them
}