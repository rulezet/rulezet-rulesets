rule TTP_XOR_WriteProcessMemory_b01d {
  strings:
    $key_b01d = { e7 6f [2] d5 4d [2] d3 78 [2] fd 78 [2] c2 64 }

  condition:
    any of them
}