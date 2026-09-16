rule TTP_XOR_WriteProcessMemory_6dad {
  strings:
    $key_6dad = { 3a df [2] 08 fd [2] 0e c8 [2] 20 c8 [2] 1f d4 }

  condition:
    any of them
}