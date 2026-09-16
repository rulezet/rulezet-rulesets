rule TTP_XOR_WriteProcessMemory_145c {
  strings:
    $key_145c = { 43 2e [2] 71 0c [2] 77 39 [2] 59 39 [2] 66 25 }

  condition:
    any of them
}