rule TTP_XOR_WriteProcessMemory_b3cf {
  strings:
    $key_b3cf = { e4 bd [2] d6 9f [2] d0 aa [2] fe aa [2] c1 b6 }

  condition:
    any of them
}