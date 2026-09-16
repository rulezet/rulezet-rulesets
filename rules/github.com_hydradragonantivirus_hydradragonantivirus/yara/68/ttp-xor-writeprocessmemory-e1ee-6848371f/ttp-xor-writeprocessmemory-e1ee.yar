rule TTP_XOR_WriteProcessMemory_e1ee {
  strings:
    $key_e1ee = { b6 9c [2] 84 be [2] 82 8b [2] ac 8b [2] 93 97 }

  condition:
    any of them
}