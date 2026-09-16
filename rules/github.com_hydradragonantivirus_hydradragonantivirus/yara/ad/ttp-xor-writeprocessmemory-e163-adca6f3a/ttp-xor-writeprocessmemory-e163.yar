rule TTP_XOR_WriteProcessMemory_e163 {
  strings:
    $key_e163 = { b6 11 [2] 84 33 [2] 82 06 [2] ac 06 [2] 93 1a }

  condition:
    any of them
}