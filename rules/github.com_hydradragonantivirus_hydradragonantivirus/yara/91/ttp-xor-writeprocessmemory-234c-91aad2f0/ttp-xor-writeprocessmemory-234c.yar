rule TTP_XOR_WriteProcessMemory_234c {
  strings:
    $key_234c = { 74 3e [2] 46 1c [2] 40 29 [2] 6e 29 [2] 51 35 }

  condition:
    any of them
}