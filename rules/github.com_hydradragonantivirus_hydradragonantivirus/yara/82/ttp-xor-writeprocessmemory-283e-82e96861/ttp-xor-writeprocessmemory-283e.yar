rule TTP_XOR_WriteProcessMemory_283e {
  strings:
    $key_283e = { 7f 4c [2] 4d 6e [2] 4b 5b [2] 65 5b [2] 5a 47 }

  condition:
    any of them
}