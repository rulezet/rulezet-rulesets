rule TTP_XOR_WriteProcessMemory_438d {
  strings:
    $key_438d = { 14 ff [2] 26 dd [2] 20 e8 [2] 0e e8 [2] 31 f4 }

  condition:
    any of them
}