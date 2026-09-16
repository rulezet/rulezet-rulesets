rule TTP_XOR_WriteProcessMemory_775c {
  strings:
    $key_775c = { 20 2e [2] 12 0c [2] 14 39 [2] 3a 39 [2] 05 25 }

  condition:
    any of them
}