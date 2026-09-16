rule TTP_XOR_WriteProcessMemory_08a8 {
  strings:
    $key_08a8 = { 5f da [2] 6d f8 [2] 6b cd [2] 45 cd [2] 7a d1 }

  condition:
    any of them
}