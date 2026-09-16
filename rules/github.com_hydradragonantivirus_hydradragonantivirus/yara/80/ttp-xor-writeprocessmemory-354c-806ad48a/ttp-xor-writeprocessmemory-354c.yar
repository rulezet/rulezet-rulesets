rule TTP_XOR_WriteProcessMemory_354c {
  strings:
    $key_354c = { 62 3e [2] 50 1c [2] 56 29 [2] 78 29 [2] 47 35 }

  condition:
    any of them
}