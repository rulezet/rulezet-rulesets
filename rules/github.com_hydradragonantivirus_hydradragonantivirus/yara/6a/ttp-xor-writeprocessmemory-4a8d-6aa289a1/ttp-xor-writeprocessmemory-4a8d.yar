rule TTP_XOR_WriteProcessMemory_4a8d {
  strings:
    $key_4a8d = { 1d ff [2] 2f dd [2] 29 e8 [2] 07 e8 [2] 38 f4 }

  condition:
    any of them
}