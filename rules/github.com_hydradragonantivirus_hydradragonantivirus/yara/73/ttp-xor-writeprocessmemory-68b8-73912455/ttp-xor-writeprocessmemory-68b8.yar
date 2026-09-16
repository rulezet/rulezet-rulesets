rule TTP_XOR_WriteProcessMemory_68b8 {
  strings:
    $key_68b8 = { 3f ca [2] 0d e8 [2] 0b dd [2] 25 dd [2] 1a c1 }

  condition:
    any of them
}