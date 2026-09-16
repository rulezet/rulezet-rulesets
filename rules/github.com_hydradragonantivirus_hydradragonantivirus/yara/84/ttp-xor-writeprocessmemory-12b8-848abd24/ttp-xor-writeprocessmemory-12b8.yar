rule TTP_XOR_WriteProcessMemory_12b8 {
  strings:
    $key_12b8 = { 45 ca [2] 77 e8 [2] 71 dd [2] 5f dd [2] 60 c1 }

  condition:
    any of them
}