rule TTP_XOR_WriteProcessMemory_738d {
  strings:
    $key_738d = { 24 ff [2] 16 dd [2] 10 e8 [2] 3e e8 [2] 01 f4 }

  condition:
    any of them
}