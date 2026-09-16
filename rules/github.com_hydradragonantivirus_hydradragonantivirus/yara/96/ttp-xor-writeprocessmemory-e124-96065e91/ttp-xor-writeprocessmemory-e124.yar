rule TTP_XOR_WriteProcessMemory_e124 {
  strings:
    $key_e124 = { b6 56 [2] 84 74 [2] 82 41 [2] ac 41 [2] 93 5d }

  condition:
    any of them
}