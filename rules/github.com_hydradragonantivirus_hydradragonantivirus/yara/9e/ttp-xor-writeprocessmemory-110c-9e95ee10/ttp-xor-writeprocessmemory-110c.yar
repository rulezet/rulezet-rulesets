rule TTP_XOR_WriteProcessMemory_110c {
  strings:
    $key_110c = { 46 7e [2] 74 5c [2] 72 69 [2] 5c 69 [2] 63 75 }

  condition:
    any of them
}