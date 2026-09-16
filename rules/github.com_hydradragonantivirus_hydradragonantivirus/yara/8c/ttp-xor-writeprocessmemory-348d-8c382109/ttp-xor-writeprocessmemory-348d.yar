rule TTP_XOR_WriteProcessMemory_348d {
  strings:
    $key_348d = { 63 ff [2] 51 dd [2] 57 e8 [2] 79 e8 [2] 46 f4 }

  condition:
    any of them
}