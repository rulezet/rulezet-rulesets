rule TTP_XOR_WriteProcessMemory_e104 {
  strings:
    $key_e104 = { b6 76 [2] 84 54 [2] 82 61 [2] ac 61 [2] 93 7d }

  condition:
    any of them
}