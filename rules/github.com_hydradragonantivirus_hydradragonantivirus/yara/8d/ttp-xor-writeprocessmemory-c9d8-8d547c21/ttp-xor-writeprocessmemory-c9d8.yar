rule TTP_XOR_WriteProcessMemory_c9d8 {
  strings:
    $key_c9d8 = { 9e aa [2] ac 88 [2] aa bd [2] 84 bd [2] bb a1 }

  condition:
    any of them
}