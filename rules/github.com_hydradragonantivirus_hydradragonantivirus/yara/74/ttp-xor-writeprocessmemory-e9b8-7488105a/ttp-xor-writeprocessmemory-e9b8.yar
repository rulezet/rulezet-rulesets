rule TTP_XOR_WriteProcessMemory_e9b8 {
  strings:
    $key_e9b8 = { be ca [2] 8c e8 [2] 8a dd [2] a4 dd [2] 9b c1 }

  condition:
    any of them
}