rule TTP_XOR_WriteProcessMemory_09b8 {
  strings:
    $key_09b8 = { 5e ca [2] 6c e8 [2] 6a dd [2] 44 dd [2] 7b c1 }

  condition:
    any of them
}