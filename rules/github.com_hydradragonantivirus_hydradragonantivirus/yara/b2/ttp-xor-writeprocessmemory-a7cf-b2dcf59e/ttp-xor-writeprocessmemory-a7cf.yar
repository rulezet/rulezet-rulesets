rule TTP_XOR_WriteProcessMemory_a7cf {
  strings:
    $key_a7cf = { f0 bd [2] c2 9f [2] c4 aa [2] ea aa [2] d5 b6 }

  condition:
    any of them
}