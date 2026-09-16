rule TTP_XOR_WriteProcessMemory_278d {
  strings:
    $key_278d = { 70 ff [2] 42 dd [2] 44 e8 [2] 6a e8 [2] 55 f4 }

  condition:
    any of them
}