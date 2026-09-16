rule TTP_XOR_WriteProcessMemory_e6b8 {
  strings:
    $key_e6b8 = { b1 ca [2] 83 e8 [2] 85 dd [2] ab dd [2] 94 c1 }

  condition:
    any of them
}