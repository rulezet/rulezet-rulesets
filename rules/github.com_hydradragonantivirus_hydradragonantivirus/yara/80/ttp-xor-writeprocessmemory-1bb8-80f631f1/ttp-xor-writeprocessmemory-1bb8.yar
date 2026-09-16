rule TTP_XOR_WriteProcessMemory_1bb8 {
  strings:
    $key_1bb8 = { 4c ca [2] 7e e8 [2] 78 dd [2] 56 dd [2] 69 c1 }

  condition:
    any of them
}