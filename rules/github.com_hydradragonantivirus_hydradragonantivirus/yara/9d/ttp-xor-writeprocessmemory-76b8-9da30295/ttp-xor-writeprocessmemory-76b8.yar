rule TTP_XOR_WriteProcessMemory_76b8 {
  strings:
    $key_76b8 = { 21 ca [2] 13 e8 [2] 15 dd [2] 3b dd [2] 04 c1 }

  condition:
    any of them
}