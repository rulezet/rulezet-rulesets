rule TTP_XOR_WriteProcessMemory_f6cf {
  strings:
    $key_f6cf = { a1 bd [2] 93 9f [2] 95 aa [2] bb aa [2] 84 b6 }

  condition:
    any of them
}