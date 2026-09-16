rule TTP_XOR_WriteProcessMemory_3d8d {
  strings:
    $key_3d8d = { 6a ff [2] 58 dd [2] 5e e8 [2] 70 e8 [2] 4f f4 }

  condition:
    any of them
}