rule TTP_XOR_WriteProcessMemory_b58d {
  strings:
    $key_b58d = { e2 ff [2] d0 dd [2] d6 e8 [2] f8 e8 [2] c7 f4 }

  condition:
    any of them
}