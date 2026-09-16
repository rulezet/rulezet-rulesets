rule TTP_XOR_WriteProcessMemory_51b8 {
  strings:
    $key_51b8 = { 06 ca [2] 34 e8 [2] 32 dd [2] 1c dd [2] 23 c1 }

  condition:
    any of them
}