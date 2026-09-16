rule TTP_XOR_WriteProcessMemory_e148 {
  strings:
    $key_e148 = { b6 3a [2] 84 18 [2] 82 2d [2] ac 2d [2] 93 31 }

  condition:
    any of them
}