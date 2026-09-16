rule TTP_XOR_WriteProcessMemory_158d {
  strings:
    $key_158d = { 42 ff [2] 70 dd [2] 76 e8 [2] 58 e8 [2] 67 f4 }

  condition:
    any of them
}