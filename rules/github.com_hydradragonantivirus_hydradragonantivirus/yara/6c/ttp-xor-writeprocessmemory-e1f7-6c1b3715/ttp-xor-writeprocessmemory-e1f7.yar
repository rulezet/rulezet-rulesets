rule TTP_XOR_WriteProcessMemory_e1f7 {
  strings:
    $key_e1f7 = { b6 85 [2] 84 a7 [2] 82 92 [2] ac 92 [2] 93 8e }

  condition:
    any of them
}