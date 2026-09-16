rule TTP_XOR_WriteProcessMemory_143c {
  strings:
    $key_143c = { 43 4e [2] 71 6c [2] 77 59 [2] 59 59 [2] 66 45 }

  condition:
    any of them
}