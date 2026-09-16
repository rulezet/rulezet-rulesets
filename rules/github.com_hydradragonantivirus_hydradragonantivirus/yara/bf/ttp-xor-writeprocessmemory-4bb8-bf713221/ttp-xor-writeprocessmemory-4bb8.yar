rule TTP_XOR_WriteProcessMemory_4bb8 {
  strings:
    $key_4bb8 = { 1c ca [2] 2e e8 [2] 28 dd [2] 06 dd [2] 39 c1 }

  condition:
    any of them
}