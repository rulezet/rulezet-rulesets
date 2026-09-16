rule TTP_XOR_WriteProcessMemory_a0cf {
  strings:
    $key_a0cf = { f7 bd [2] c5 9f [2] c3 aa [2] ed aa [2] d2 b6 }

  condition:
    any of them
}