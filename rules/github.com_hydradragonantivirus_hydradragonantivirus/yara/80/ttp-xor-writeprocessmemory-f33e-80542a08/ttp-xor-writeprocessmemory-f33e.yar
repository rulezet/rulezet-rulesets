rule TTP_XOR_WriteProcessMemory_f33e {
  strings:
    $key_f33e = { a4 4c [2] 96 6e [2] 90 5b [2] be 5b [2] 81 47 }

  condition:
    any of them
}