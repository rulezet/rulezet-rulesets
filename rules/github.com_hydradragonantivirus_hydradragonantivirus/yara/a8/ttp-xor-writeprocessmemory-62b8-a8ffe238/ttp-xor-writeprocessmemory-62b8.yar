rule TTP_XOR_WriteProcessMemory_62b8 {
  strings:
    $key_62b8 = { 35 ca [2] 07 e8 [2] 01 dd [2] 2f dd [2] 10 c1 }

  condition:
    any of them
}