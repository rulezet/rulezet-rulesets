rule TTP_XOR_WriteProcessMemory_0d8d {
  strings:
    $key_0d8d = { 5a ff [2] 68 dd [2] 6e e8 [2] 40 e8 [2] 7f f4 }

  condition:
    any of them
}