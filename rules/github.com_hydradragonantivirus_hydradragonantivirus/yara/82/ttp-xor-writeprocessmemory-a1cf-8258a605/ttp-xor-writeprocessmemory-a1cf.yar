rule TTP_XOR_WriteProcessMemory_a1cf {
  strings:
    $key_a1cf = { f6 bd [2] c4 9f [2] c2 aa [2] ec aa [2] d3 b6 }

  condition:
    any of them
}