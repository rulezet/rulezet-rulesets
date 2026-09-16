rule TTP_XOR_WriteProcessMemory_2e8d {
  strings:
    $key_2e8d = { 79 ff [2] 4b dd [2] 4d e8 [2] 63 e8 [2] 5c f4 }

  condition:
    any of them
}