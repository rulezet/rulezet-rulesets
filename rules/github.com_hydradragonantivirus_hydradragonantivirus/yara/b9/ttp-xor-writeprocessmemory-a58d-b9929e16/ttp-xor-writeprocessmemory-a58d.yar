rule TTP_XOR_WriteProcessMemory_a58d {
  strings:
    $key_a58d = { f2 ff [2] c0 dd [2] c6 e8 [2] e8 e8 [2] d7 f4 }

  condition:
    any of them
}