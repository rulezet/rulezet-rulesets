rule TTP_XOR_WriteProcessMemory_e8a8 {
  strings:
    $key_e8a8 = { bf da [2] 8d f8 [2] 8b cd [2] a5 cd [2] 9a d1 }

  condition:
    any of them
}