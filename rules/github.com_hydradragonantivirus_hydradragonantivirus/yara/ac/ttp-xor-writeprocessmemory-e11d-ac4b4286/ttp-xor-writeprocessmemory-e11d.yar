rule TTP_XOR_WriteProcessMemory_e11d {
  strings:
    $key_e11d = { b6 6f [2] 84 4d [2] 82 78 [2] ac 78 [2] 93 64 }

  condition:
    any of them
}