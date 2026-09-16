rule TTP_XOR_WriteProcessMemory_61b8 {
  strings:
    $key_61b8 = { 36 ca [2] 04 e8 [2] 02 dd [2] 2c dd [2] 13 c1 }

  condition:
    any of them
}