rule TTP_XOR_WriteProcessMemory_e68d {
  strings:
    $key_e68d = { b1 ff [2] 83 dd [2] 85 e8 [2] ab e8 [2] 94 f4 }

  condition:
    any of them
}