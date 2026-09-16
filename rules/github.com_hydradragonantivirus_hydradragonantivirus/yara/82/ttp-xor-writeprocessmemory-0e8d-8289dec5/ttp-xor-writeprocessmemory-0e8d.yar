rule TTP_XOR_WriteProcessMemory_0e8d {
  strings:
    $key_0e8d = { 59 ff [2] 6b dd [2] 6d e8 [2] 43 e8 [2] 7c f4 }

  condition:
    any of them
}