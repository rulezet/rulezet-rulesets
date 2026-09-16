rule TTP_XOR_WriteProcessMemory_e1ea {
  strings:
    $key_e1ea = { b6 98 [2] 84 ba [2] 82 8f [2] ac 8f [2] 93 93 }

  condition:
    any of them
}