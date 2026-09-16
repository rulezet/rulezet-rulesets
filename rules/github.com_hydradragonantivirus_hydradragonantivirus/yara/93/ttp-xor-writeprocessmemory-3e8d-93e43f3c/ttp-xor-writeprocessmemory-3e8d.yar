rule TTP_XOR_WriteProcessMemory_3e8d {
  strings:
    $key_3e8d = { 69 ff [2] 5b dd [2] 5d e8 [2] 73 e8 [2] 4c f4 }

  condition:
    any of them
}