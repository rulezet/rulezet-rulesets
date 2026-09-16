rule TTP_XOR_WriteProcessMemory_e15d {
  strings:
    $key_e15d = { b6 2f [2] 84 0d [2] 82 38 [2] ac 38 [2] 93 24 }

  condition:
    any of them
}