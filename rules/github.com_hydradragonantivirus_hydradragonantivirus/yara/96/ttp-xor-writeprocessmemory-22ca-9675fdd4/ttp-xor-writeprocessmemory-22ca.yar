rule TTP_XOR_WriteProcessMemory_22ca {
  strings:
    $key_22ca = { 75 b8 [2] 47 9a [2] 41 af [2] 6f af [2] 50 b3 }

  condition:
    any of them
}