rule TTP_XOR_WriteProcessMemory_530c {
  strings:
    $key_530c = { 04 7e [2] 36 5c [2] 30 69 [2] 1e 69 [2] 21 75 }

  condition:
    any of them
}