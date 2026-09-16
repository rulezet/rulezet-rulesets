rule TTP_XOR_WriteProcessMemory_e1d8 {
  strings:
    $key_e1d8 = { b6 aa [2] 84 88 [2] 82 bd [2] ac bd [2] 93 a1 }

  condition:
    any of them
}