rule TTP_XOR_WriteProcessMemory_72b8 {
  strings:
    $key_72b8 = { 25 ca [2] 17 e8 [2] 11 dd [2] 3f dd [2] 00 c1 }

  condition:
    any of them
}