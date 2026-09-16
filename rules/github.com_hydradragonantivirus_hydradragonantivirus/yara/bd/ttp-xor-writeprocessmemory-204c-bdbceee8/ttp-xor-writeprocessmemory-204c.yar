rule TTP_XOR_WriteProcessMemory_204c {
  strings:
    $key_204c = { 77 3e [2] 45 1c [2] 43 29 [2] 6d 29 [2] 52 35 }

  condition:
    any of them
}