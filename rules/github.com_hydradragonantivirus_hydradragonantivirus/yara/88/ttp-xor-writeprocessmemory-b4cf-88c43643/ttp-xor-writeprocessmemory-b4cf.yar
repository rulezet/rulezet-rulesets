rule TTP_XOR_WriteProcessMemory_b4cf {
  strings:
    $key_b4cf = { e3 bd [2] d1 9f [2] d7 aa [2] f9 aa [2] c6 b6 }

  condition:
    any of them
}