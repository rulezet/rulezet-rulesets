rule TTP_XOR_WriteProcessMemory_508d {
  strings:
    $key_508d = { 07 ff [2] 35 dd [2] 33 e8 [2] 1d e8 [2] 22 f4 }

  condition:
    any of them
}