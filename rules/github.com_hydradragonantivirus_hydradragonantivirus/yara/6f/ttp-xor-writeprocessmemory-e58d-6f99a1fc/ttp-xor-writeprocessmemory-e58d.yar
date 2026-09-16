rule TTP_XOR_WriteProcessMemory_e58d {
  strings:
    $key_e58d = { b2 ff [2] 80 dd [2] 86 e8 [2] a8 e8 [2] 97 f4 }

  condition:
    any of them
}