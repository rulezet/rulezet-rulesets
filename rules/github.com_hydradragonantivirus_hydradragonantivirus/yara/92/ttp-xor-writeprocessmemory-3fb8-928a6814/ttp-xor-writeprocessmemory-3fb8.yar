rule TTP_XOR_WriteProcessMemory_3fb8 {
  strings:
    $key_3fb8 = { 68 ca [2] 5a e8 [2] 5c dd [2] 72 dd [2] 4d c1 }

  condition:
    any of them
}