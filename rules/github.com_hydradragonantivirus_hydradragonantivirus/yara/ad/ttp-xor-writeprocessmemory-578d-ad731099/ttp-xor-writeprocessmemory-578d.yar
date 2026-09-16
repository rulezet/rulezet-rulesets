rule TTP_XOR_WriteProcessMemory_578d {
  strings:
    $key_578d = { 00 ff [2] 32 dd [2] 34 e8 [2] 1a e8 [2] 25 f4 }

  condition:
    any of them
}