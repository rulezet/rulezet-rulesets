rule TTP_XOR_WriteProcessMemory_e1cf {
  strings:
    $key_e1cf = { b6 bd [2] 84 9f [2] 82 aa [2] ac aa [2] 93 b6 }

  condition:
    any of them
}