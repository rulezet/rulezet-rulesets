rule TTP_XOR_WriteProcessMemory_e2b8 {
  strings:
    $key_e2b8 = { b5 ca [2] 87 e8 [2] 81 dd [2] af dd [2] 90 c1 }

  condition:
    any of them
}