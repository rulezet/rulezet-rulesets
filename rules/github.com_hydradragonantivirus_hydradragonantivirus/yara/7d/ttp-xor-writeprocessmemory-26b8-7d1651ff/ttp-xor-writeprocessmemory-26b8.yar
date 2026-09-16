rule TTP_XOR_WriteProcessMemory_26b8 {
  strings:
    $key_26b8 = { 71 ca [2] 43 e8 [2] 45 dd [2] 6b dd [2] 54 c1 }

  condition:
    any of them
}