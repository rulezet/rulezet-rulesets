rule TTP_XOR_WriteProcessMemory_39b8 {
  strings:
    $key_39b8 = { 6e ca [2] 5c e8 [2] 5a dd [2] 74 dd [2] 4b c1 }

  condition:
    any of them
}