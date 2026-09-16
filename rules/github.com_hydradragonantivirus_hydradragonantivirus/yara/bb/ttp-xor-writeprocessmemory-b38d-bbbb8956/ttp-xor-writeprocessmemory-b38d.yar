rule TTP_XOR_WriteProcessMemory_b38d {
  strings:
    $key_b38d = { e4 ff [2] d6 dd [2] d0 e8 [2] fe e8 [2] c1 f4 }

  condition:
    any of them
}