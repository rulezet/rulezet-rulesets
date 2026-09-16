rule TTP_XOR_WriteProcessMemory_e847 {
  strings:
    $key_e847 = { bf 35 [2] 8d 17 [2] 8b 22 [2] a5 22 [2] 9a 3e }

  condition:
    any of them
}