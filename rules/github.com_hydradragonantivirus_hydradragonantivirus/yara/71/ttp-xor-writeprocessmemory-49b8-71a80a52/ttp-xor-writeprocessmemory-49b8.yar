rule TTP_XOR_WriteProcessMemory_49b8 {
  strings:
    $key_49b8 = { 1e ca [2] 2c e8 [2] 2a dd [2] 04 dd [2] 3b c1 }

  condition:
    any of them
}