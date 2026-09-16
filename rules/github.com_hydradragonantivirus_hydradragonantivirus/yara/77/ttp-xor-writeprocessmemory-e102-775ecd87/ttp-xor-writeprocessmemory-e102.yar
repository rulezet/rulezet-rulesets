rule TTP_XOR_WriteProcessMemory_e102 {
  strings:
    $key_e102 = { b6 70 [2] 84 52 [2] 82 67 [2] ac 67 [2] 93 7b }

  condition:
    any of them
}