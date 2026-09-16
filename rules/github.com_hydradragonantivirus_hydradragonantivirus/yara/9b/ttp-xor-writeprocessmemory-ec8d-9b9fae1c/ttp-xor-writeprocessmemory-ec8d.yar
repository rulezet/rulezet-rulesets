rule TTP_XOR_WriteProcessMemory_ec8d {
  strings:
    $key_ec8d = { bb ff [2] 89 dd [2] 8f e8 [2] a1 e8 [2] 9e f4 }

  condition:
    any of them
}