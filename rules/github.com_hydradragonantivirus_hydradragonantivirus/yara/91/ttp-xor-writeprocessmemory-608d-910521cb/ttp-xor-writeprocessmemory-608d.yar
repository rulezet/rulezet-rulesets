rule TTP_XOR_WriteProcessMemory_608d {
  strings:
    $key_608d = { 37 ff [2] 05 dd [2] 03 e8 [2] 2d e8 [2] 12 f4 }

  condition:
    any of them
}