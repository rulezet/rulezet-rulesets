rule TTP_XOR_WriteProcessMemory_30b8 {
  strings:
    $key_30b8 = { 67 ca [2] 55 e8 [2] 53 dd [2] 7d dd [2] 42 c1 }

  condition:
    any of them
}