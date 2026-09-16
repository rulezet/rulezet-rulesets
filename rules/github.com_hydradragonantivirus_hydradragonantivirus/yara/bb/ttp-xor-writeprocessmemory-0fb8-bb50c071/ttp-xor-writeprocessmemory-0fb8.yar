rule TTP_XOR_WriteProcessMemory_0fb8 {
  strings:
    $key_0fb8 = { 58 ca [2] 6a e8 [2] 6c dd [2] 42 dd [2] 7d c1 }

  condition:
    any of them
}