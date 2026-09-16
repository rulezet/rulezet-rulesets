rule TTP_XOR_WriteProcessMemory_7d8d {
  strings:
    $key_7d8d = { 2a ff [2] 18 dd [2] 1e e8 [2] 30 e8 [2] 0f f4 }

  condition:
    any of them
}