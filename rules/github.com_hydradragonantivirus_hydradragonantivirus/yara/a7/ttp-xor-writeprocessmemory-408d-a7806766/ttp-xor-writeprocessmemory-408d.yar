rule TTP_XOR_WriteProcessMemory_408d {
  strings:
    $key_408d = { 17 ff [2] 25 dd [2] 23 e8 [2] 0d e8 [2] 32 f4 }

  condition:
    any of them
}