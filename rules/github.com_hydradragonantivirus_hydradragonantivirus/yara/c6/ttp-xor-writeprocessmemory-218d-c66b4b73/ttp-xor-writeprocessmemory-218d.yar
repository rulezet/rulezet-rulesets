rule TTP_XOR_WriteProcessMemory_218d {
  strings:
    $key_218d = { 76 ff [2] 44 dd [2] 42 e8 [2] 6c e8 [2] 53 f4 }

  condition:
    any of them
}