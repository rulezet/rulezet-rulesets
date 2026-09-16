rule TTP_XOR_WriteProcessMemory_b0fa {
  strings:
    $key_b0fa = { e7 88 [2] d5 aa [2] d3 9f [2] fd 9f [2] c2 83 }

  condition:
    any of them
}