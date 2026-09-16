rule TTP_XOR_WriteProcessMemory_78b8 {
  strings:
    $key_78b8 = { 2f ca [2] 1d e8 [2] 1b dd [2] 35 dd [2] 0a c1 }

  condition:
    any of them
}