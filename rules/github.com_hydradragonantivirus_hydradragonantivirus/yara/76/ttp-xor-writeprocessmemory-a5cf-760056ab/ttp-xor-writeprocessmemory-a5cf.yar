rule TTP_XOR_WriteProcessMemory_a5cf {
  strings:
    $key_a5cf = { f2 bd [2] c0 9f [2] c6 aa [2] e8 aa [2] d7 b6 }

  condition:
    any of them
}