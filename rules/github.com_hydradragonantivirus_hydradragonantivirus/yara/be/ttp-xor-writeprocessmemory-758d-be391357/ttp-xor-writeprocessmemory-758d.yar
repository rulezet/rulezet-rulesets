rule TTP_XOR_WriteProcessMemory_758d {
  strings:
    $key_758d = { 22 ff [2] 10 dd [2] 16 e8 [2] 38 e8 [2] 07 f4 }

  condition:
    any of them
}