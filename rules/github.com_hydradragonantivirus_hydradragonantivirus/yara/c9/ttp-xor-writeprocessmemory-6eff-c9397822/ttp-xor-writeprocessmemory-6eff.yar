rule TTP_XOR_WriteProcessMemory_6eff {
  strings:
    $key_6eff = { 39 8d [2] 0b af [2] 0d 9a [2] 23 9a [2] 1c 86 }

  condition:
    any of them
}