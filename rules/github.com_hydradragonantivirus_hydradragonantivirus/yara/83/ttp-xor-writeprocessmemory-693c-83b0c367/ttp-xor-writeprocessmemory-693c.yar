rule TTP_XOR_WriteProcessMemory_693c {
  strings:
    $key_693c = { 3e 4e [2] 0c 6c [2] 0a 59 [2] 24 59 [2] 1b 45 }

  condition:
    any of them
}