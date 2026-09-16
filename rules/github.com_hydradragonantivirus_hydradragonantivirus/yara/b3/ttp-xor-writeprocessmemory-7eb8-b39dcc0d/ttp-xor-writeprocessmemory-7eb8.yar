rule TTP_XOR_WriteProcessMemory_7eb8 {
  strings:
    $key_7eb8 = { 29 ca [2] 1b e8 [2] 1d dd [2] 33 dd [2] 0c c1 }

  condition:
    any of them
}