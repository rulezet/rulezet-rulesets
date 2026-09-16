rule TTP_XOR_WriteProcessMemory_b08d {
  strings:
    $key_b08d = { e7 ff [2] d5 dd [2] d3 e8 [2] fd e8 [2] c2 f4 }

  condition:
    any of them
}