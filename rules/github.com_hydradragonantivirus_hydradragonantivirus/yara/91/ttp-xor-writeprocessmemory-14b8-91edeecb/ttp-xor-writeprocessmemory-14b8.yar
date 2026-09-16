rule TTP_XOR_WriteProcessMemory_14b8 {
  strings:
    $key_14b8 = { 43 ca [2] 71 e8 [2] 77 dd [2] 59 dd [2] 66 c1 }

  condition:
    any of them
}