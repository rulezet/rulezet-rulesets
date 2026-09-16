rule TTP_XOR_WriteProcessMemory_693e {
  strings:
    $key_693e = { 3e 4c [2] 0c 6e [2] 0a 5b [2] 24 5b [2] 1b 47 }

  condition:
    any of them
}