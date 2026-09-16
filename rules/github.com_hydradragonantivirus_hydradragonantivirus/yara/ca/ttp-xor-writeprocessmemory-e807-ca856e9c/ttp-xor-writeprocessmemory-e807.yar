rule TTP_XOR_WriteProcessMemory_e807 {
  strings:
    $key_e807 = { bf 75 [2] 8d 57 [2] 8b 62 [2] a5 62 [2] 9a 7e }

  condition:
    any of them
}