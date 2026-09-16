rule TTP_XOR_WriteProcessMemory_48b8 {
  strings:
    $key_48b8 = { 1f ca [2] 2d e8 [2] 2b dd [2] 05 dd [2] 3a c1 }

  condition:
    any of them
}