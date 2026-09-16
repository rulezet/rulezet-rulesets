rule TTP_XOR_WriteProcessMemory_90b8 {
  strings:
    $key_90b8 = { c7 ca [2] f5 e8 [2] f3 dd [2] dd dd [2] e2 c1 }

  condition:
    any of them
}