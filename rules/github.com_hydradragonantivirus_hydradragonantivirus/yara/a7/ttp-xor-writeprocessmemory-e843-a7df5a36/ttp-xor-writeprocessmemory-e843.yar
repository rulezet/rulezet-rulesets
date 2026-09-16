rule TTP_XOR_WriteProcessMemory_e843 {
  strings:
    $key_e843 = { bf 31 [2] 8d 13 [2] 8b 26 [2] a5 26 [2] 9a 3a }

  condition:
    any of them
}