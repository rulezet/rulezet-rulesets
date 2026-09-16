rule TTP_XOR_WriteProcessMemory_00b8 {
  strings:
    $key_00b8 = { 57 ca [2] 65 e8 [2] 63 dd [2] 4d dd [2] 72 c1 }

  condition:
    any of them
}