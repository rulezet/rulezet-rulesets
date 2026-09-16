rule TTP_XOR_WriteProcessMemory_42b8 {
  strings:
    $key_42b8 = { 15 ca [2] 27 e8 [2] 21 dd [2] 0f dd [2] 30 c1 }

  condition:
    any of them
}