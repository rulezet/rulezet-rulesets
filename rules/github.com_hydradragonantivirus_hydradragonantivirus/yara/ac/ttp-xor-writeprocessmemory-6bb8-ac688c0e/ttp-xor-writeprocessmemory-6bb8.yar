rule TTP_XOR_WriteProcessMemory_6bb8 {
  strings:
    $key_6bb8 = { 3c ca [2] 0e e8 [2] 08 dd [2] 26 dd [2] 19 c1 }

  condition:
    any of them
}