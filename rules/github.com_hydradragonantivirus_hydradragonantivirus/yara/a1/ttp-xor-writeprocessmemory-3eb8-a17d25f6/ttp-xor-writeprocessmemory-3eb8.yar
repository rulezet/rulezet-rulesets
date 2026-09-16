rule TTP_XOR_WriteProcessMemory_3eb8 {
  strings:
    $key_3eb8 = { 69 ca [2] 5b e8 [2] 5d dd [2] 73 dd [2] 4c c1 }

  condition:
    any of them
}