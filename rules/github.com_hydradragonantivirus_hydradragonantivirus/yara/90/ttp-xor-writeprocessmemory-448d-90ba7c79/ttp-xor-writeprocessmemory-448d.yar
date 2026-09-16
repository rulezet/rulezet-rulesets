rule TTP_XOR_WriteProcessMemory_448d {
  strings:
    $key_448d = { 13 ff [2] 21 dd [2] 27 e8 [2] 09 e8 [2] 36 f4 }

  condition:
    any of them
}