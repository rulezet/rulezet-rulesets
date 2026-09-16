rule TTP_XOR_WriteProcessMemory_e13d {
  strings:
    $key_e13d = { b6 4f [2] 84 6d [2] 82 58 [2] ac 58 [2] 93 44 }

  condition:
    any of them
}