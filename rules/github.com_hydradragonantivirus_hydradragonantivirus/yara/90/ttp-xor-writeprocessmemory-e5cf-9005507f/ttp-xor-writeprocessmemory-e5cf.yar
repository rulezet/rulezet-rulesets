rule TTP_XOR_WriteProcessMemory_e5cf {
  strings:
    $key_e5cf = { b2 bd [2] 80 9f [2] 86 aa [2] a8 aa [2] 97 b6 }

  condition:
    any of them
}