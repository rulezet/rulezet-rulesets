rule TTP_XOR_WriteProcessMemory_1d8d {
  strings:
    $key_1d8d = { 4a ff [2] 78 dd [2] 7e e8 [2] 50 e8 [2] 6f f4 }

  condition:
    any of them
}