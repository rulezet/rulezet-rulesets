rule TTP_XOR_WriteProcessMemory_e8e9 {
  strings:
    $key_e8e9 = { bf 9b [2] 8d b9 [2] 8b 8c [2] a5 8c [2] 9a 90 }

  condition:
    any of them
}