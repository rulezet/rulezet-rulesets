rule TTP_XOR_WriteProcessMemory_e88d {
  strings:
    $key_e88d = { bf ff [2] 8d dd [2] 8b e8 [2] a5 e8 [2] 9a f4 }

  condition:
    any of them
}