rule TTP_XOR_WriteProcessMemory_e846 {
  strings:
    $key_e846 = { bf 34 [2] 8d 16 [2] 8b 23 [2] a5 23 [2] 9a 3f }

  condition:
    any of them
}