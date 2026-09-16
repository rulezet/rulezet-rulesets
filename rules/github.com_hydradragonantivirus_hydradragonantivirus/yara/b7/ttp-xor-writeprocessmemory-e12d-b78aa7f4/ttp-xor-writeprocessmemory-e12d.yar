rule TTP_XOR_WriteProcessMemory_e12d {
  strings:
    $key_e12d = { b6 5f [2] 84 7d [2] 82 48 [2] ac 48 [2] 93 54 }

  condition:
    any of them
}