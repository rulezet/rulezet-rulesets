rule TTP_XOR_WriteProcessMemory_2fb8 {
  strings:
    $key_2fb8 = { 78 ca [2] 4a e8 [2] 4c dd [2] 62 dd [2] 5d c1 }

  condition:
    any of them
}