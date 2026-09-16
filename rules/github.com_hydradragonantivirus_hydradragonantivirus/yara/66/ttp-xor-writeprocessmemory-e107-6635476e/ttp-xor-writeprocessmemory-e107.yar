rule TTP_XOR_WriteProcessMemory_e107 {
  strings:
    $key_e107 = { b6 75 [2] 84 57 [2] 82 62 [2] ac 62 [2] 93 7e }

  condition:
    any of them
}