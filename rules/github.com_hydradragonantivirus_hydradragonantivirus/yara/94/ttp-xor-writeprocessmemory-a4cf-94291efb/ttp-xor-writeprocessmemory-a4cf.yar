rule TTP_XOR_WriteProcessMemory_a4cf {
  strings:
    $key_a4cf = { f3 bd [2] c1 9f [2] c7 aa [2] e9 aa [2] d6 b6 }

  condition:
    any of them
}