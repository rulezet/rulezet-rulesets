rule TTP_XOR_WriteProcessMemory_e7cf {
  strings:
    $key_e7cf = { b0 bd [2] 82 9f [2] 84 aa [2] aa aa [2] 95 b6 }

  condition:
    any of them
}