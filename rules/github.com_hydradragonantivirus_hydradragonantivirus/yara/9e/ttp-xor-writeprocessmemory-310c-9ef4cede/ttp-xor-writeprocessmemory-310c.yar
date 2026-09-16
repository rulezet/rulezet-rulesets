rule TTP_XOR_WriteProcessMemory_310c {
  strings:
    $key_310c = { 66 7e [2] 54 5c [2] 52 69 [2] 7c 69 [2] 43 75 }

  condition:
    any of them
}