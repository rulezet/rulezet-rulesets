rule TTP_XOR_WriteProcessMemory_e118 {
  strings:
    $key_e118 = { b6 6a [2] 84 48 [2] 82 7d [2] ac 7d [2] 93 61 }

  condition:
    any of them
}