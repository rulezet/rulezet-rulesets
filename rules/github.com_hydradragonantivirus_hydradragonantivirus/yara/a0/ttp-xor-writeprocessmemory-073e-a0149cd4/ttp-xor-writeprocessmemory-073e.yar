rule TTP_XOR_WriteProcessMemory_073e {
  strings:
    $key_073e = { 50 4c [2] 62 6e [2] 64 5b [2] 4a 5b [2] 75 47 }

  condition:
    any of them
}