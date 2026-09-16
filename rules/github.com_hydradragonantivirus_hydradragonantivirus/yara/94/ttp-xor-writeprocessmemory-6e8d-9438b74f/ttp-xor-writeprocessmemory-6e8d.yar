rule TTP_XOR_WriteProcessMemory_6e8d {
  strings:
    $key_6e8d = { 39 ff [2] 0b dd [2] 0d e8 [2] 23 e8 [2] 1c f4 }

  condition:
    any of them
}