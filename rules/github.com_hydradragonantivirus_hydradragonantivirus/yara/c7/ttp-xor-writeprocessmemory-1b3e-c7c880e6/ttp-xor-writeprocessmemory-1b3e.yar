rule TTP_XOR_WriteProcessMemory_1b3e {
  strings:
    $key_1b3e = { 4c 4c [2] 7e 6e [2] 78 5b [2] 56 5b [2] 69 47 }

  condition:
    any of them
}