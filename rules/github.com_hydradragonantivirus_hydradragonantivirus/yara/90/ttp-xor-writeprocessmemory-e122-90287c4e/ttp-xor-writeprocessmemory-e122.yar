rule TTP_XOR_WriteProcessMemory_e122 {
  strings:
    $key_e122 = { b6 50 [2] 84 72 [2] 82 47 [2] ac 47 [2] 93 5b }

  condition:
    any of them
}