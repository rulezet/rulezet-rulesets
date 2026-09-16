rule TTP_XOR_WriteProcessMemory_520c {
  strings:
    $key_520c = { 05 7e [2] 37 5c [2] 31 69 [2] 1f 69 [2] 20 75 }

  condition:
    any of them
}