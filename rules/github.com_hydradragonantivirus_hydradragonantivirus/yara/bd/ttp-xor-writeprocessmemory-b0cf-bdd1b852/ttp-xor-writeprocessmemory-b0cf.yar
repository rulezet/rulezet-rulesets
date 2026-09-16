rule TTP_XOR_WriteProcessMemory_b0cf {
  strings:
    $key_b0cf = { e7 bd [2] d5 9f [2] d3 aa [2] fd aa [2] c2 b6 }

  condition:
    any of them
}