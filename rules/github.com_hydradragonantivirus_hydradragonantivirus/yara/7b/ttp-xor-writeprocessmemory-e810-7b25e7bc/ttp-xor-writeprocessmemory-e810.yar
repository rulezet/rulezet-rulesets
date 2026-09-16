rule TTP_XOR_WriteProcessMemory_e810 {
  strings:
    $key_e810 = { bf 62 [2] 8d 40 [2] 8b 75 [2] a5 75 [2] 9a 69 }

  condition:
    any of them
}