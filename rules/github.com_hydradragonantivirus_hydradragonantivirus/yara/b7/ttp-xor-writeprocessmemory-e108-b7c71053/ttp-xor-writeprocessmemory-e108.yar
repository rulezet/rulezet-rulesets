rule TTP_XOR_WriteProcessMemory_e108 {
  strings:
    $key_e108 = { b6 7a [2] 84 58 [2] 82 6d [2] ac 6d [2] 93 71 }

  condition:
    any of them
}