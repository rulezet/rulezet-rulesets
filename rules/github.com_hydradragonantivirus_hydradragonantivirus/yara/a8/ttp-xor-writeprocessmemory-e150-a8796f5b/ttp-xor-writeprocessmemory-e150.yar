rule TTP_XOR_WriteProcessMemory_e150 {
  strings:
    $key_e150 = { b6 22 [2] 84 00 [2] 82 35 [2] ac 35 [2] 93 29 }

  condition:
    any of them
}