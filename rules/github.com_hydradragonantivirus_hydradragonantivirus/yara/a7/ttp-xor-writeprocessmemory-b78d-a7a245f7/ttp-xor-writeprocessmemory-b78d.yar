rule TTP_XOR_WriteProcessMemory_b78d {
  strings:
    $key_b78d = { e0 ff [2] d2 dd [2] d4 e8 [2] fa e8 [2] c5 f4 }

  condition:
    any of them
}