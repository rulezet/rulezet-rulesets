rule TTP_XOR_WriteProcessMemory_527c {
  strings:
    $key_527c = { 05 0e [2] 37 2c [2] 31 19 [2] 1f 19 [2] 20 05 }

  condition:
    any of them
}