rule TTP_XOR_WriteProcessMemory_5eff {
  strings:
    $key_5eff = { 09 8d [2] 3b af [2] 3d 9a [2] 13 9a [2] 2c 86 }

  condition:
    any of them
}