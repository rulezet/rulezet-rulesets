rule TTP_XOR_WriteProcessMemory_138d {
  strings:
    $key_138d = { 44 ff [2] 76 dd [2] 70 e8 [2] 5e e8 [2] 61 f4 }

  condition:
    any of them
}