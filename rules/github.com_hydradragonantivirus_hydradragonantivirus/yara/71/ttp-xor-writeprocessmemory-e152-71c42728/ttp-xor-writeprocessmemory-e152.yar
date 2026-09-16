rule TTP_XOR_WriteProcessMemory_e152 {
  strings:
    $key_e152 = { b6 20 [2] 84 02 [2] 82 37 [2] ac 37 [2] 93 2b }

  condition:
    any of them
}