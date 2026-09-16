rule TTP_XOR_WriteProcessMemory_550c {
  strings:
    $key_550c = { 02 7e [2] 30 5c [2] 36 69 [2] 18 69 [2] 27 75 }

  condition:
    any of them
}