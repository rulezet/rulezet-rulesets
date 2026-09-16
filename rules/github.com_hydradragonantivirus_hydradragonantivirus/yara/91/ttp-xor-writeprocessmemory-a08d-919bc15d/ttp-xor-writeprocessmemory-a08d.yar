rule TTP_XOR_WriteProcessMemory_a08d {
  strings:
    $key_a08d = { f7 ff [2] c5 dd [2] c3 e8 [2] ed e8 [2] d2 f4 }

  condition:
    any of them
}