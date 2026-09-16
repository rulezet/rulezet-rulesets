rule TTP_XOR_WriteProcessMemory_b18d {
  strings:
    $key_b18d = { e6 ff [2] d4 dd [2] d2 e8 [2] fc e8 [2] c3 f4 }

  condition:
    any of them
}