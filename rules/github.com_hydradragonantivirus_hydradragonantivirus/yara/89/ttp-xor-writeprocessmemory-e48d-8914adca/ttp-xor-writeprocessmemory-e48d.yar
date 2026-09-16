rule TTP_XOR_WriteProcessMemory_e48d {
  strings:
    $key_e48d = { b3 ff [2] 81 dd [2] 87 e8 [2] a9 e8 [2] 96 f4 }

  condition:
    any of them
}