rule TTP_XOR_WriteProcessMemory_6fb8 {
  strings:
    $key_6fb8 = { 38 ca [2] 0a e8 [2] 0c dd [2] 22 dd [2] 1d c1 }

  condition:
    any of them
}