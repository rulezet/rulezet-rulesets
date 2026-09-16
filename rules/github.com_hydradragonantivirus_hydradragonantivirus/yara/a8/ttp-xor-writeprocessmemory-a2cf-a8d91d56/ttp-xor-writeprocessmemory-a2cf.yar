rule TTP_XOR_WriteProcessMemory_a2cf {
  strings:
    $key_a2cf = { f5 bd [2] c7 9f [2] c1 aa [2] ef aa [2] d0 b6 }

  condition:
    any of them
}