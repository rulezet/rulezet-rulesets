rule TTP_XOR_WriteProcessMemory_eeb8 {
  strings:
    $key_eeb8 = { b9 ca [2] 8b e8 [2] 8d dd [2] a3 dd [2] 9c c1 }

  condition:
    any of them
}