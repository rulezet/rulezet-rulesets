rule TTP_XOR_WriteProcessMemory_18a8 {
  strings:
    $key_18a8 = { 4f da [2] 7d f8 [2] 7b cd [2] 55 cd [2] 6a d1 }

  condition:
    any of them
}