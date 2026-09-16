rule TTP_XOR_WriteProcessMemory_6d8d {
  strings:
    $key_6d8d = { 3a ff [2] 08 dd [2] 0e e8 [2] 20 e8 [2] 1f f4 }

  condition:
    any of them
}