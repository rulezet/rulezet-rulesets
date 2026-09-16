rule TTP_XOR_WriteProcessMemory_16b8 {
  strings:
    $key_16b8 = { 41 ca [2] 73 e8 [2] 75 dd [2] 5b dd [2] 64 c1 }

  condition:
    any of them
}