rule TTP_XOR_WriteProcessMemory_02b8 {
  strings:
    $key_02b8 = { 55 ca [2] 67 e8 [2] 61 dd [2] 4f dd [2] 70 c1 }

  condition:
    any of them
}