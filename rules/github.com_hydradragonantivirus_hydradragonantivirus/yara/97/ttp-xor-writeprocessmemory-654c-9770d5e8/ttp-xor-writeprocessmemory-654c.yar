rule TTP_XOR_WriteProcessMemory_654c {
  strings:
    $key_654c = { 32 3e [2] 00 1c [2] 06 29 [2] 28 29 [2] 17 35 }

  condition:
    any of them
}