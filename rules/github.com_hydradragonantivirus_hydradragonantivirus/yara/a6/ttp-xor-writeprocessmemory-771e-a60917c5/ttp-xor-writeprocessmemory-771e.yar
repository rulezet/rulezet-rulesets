rule TTP_XOR_WriteProcessMemory_771e {
  strings:
    $key_771e = { 20 6c [2] 12 4e [2] 14 7b [2] 3a 7b [2] 05 67 }

  condition:
    any of them
}