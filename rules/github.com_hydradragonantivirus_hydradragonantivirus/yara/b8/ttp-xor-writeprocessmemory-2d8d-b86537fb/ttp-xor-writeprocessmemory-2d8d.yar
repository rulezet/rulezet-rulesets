rule TTP_XOR_WriteProcessMemory_2d8d {
  strings:
    $key_2d8d = { 7a ff [2] 48 dd [2] 4e e8 [2] 60 e8 [2] 5f f4 }

  condition:
    any of them
}