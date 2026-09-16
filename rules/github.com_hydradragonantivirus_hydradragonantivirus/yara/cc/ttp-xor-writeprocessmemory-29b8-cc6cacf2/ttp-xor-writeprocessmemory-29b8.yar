rule TTP_XOR_WriteProcessMemory_29b8 {
  strings:
    $key_29b8 = { 7e ca [2] 4c e8 [2] 4a dd [2] 64 dd [2] 5b c1 }

  condition:
    any of them
}