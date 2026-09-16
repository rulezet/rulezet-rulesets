rule TTP_XOR_WriteProcessMemory_e860 {
  strings:
    $key_e860 = { bf 12 [2] 8d 30 [2] 8b 05 [2] a5 05 [2] 9a 19 }

  condition:
    any of them
}