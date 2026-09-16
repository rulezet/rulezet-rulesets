rule TTP_XOR_WriteProcessMemory_450c {
  strings:
    $key_450c = { 12 7e [2] 20 5c [2] 26 69 [2] 08 69 [2] 37 75 }

  condition:
    any of them
}